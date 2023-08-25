(ns dev
  "Tools for interactive development with the REPL. This file should
  not be included in a production build of the application.
  Call `(reset)` to reload modified code and (re)start the system.
  The system under development is `system`, referred from
  `com.stuartsierra.component.repl/system`.
  See also https://github.com/stuartsierra/component.repl"
  (:require
   [clj-http.client :as http]
   [clojure.datafy :refer [datafy]]
   [clojure.data.json :as json]
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.java.javadoc :refer [javadoc]]
   [clojure.pprint :refer [pprint pp]]
   [clojure.reflect :refer [reflect]]
   [clojure.repl :refer [apropos dir find-doc pst source]]
   [clojure.set :as set]
   [clojure.string :as str]
   [clojure.tools.namespace.repl :refer [refresh refresh-all clear]]
   [clojure.walk :as walk]
   [com.stuartsierra.component :as com]
   [com.stuartsierra.component.repl :refer [reset set-init start stop system]]
   [com.walmartlabs.schematic :as sc]
   [datomic.client.api :as d]
   [net.wikipunk.boot]
   [net.wikipunk.ext]
   [net.wikipunk.mop :as mop]
   [net.wikipunk.rdf :as rdf :refer [doc]]
   [net.wikipunk.datomic.boot :as db]
   [net.wikipunk.datomic.rl :as rl]
   [zprint.core :as zprint]
   [clj-fuzzy.jaro-winkler :refer [jaro-winkler]]
   [xtdb.api :as xt]))

(set-init
  (fn [_]
    (set! *print-namespace-maps* nil)
    (if-let [r (io/resource "system.edn")]
      (-> (slurp r)
          (edn/read-string)
          (sc/assemble-system))
      (throw (ex-info "system.edn is not on classpath" {})))))

(defmacro inspect
  "Evaluate forms in an implicit do and inspect the value of the last
  expression using Reveal."
  [& body]
  `(do (@user/reveal (do ~@body))
       true))

(comment
  (def boot-db (db/test-bootstrap (:db system))))

;; step 1: get an personal access token (PAT) for GitHub with public read-only permissions
;; step 2: use your PAT as an :oauth-token to fetch GitHub REST API SBOMs from public repositories
;; step 3: convert the SPDX JSON document to RDF using org.spdx/tools-java
;; step 4: parse the RDF with rdf/parse and massage the RDF/EDN into Datomic tx-data
;; step 5: transact the SBOM tx-data
;; step 6: go to step 1 when you want to add more SBOMs, else you're finished!

(defn normalize
  [str]
  (clojure.string/lower-case (clojure.string/replace str #"[\W_]+" "")))

(defn spdx-comparison
  [identifier full-name & {:keys [weight] :or {weight 0.9}}]
  (let [version      (re-find #"\d+" identifier)
        name-version (re-find #"\d+" full-name)
        base-score   (jaro-winkler (normalize identifier) (normalize full-name))]
    (if (and version name-version (= version name-version))
      base-score
      (* base-score weight))))

(def license-ids
  (set (org.spdx.library.model.license.LicenseInfoFactory/getSpdxListedLicenseIds)))

(defn match-spdx-license
  [v]
  (reduce (fn [[last-license-id last-score] license-id]
            (let [score    (spdx-comparison license-id v)]
              (if (>= score last-score)
                [license-id score]
                [last-license-id last-score])))
          [nil 0.0]
          license-ids))

(defn get-sbom
  "For a given owner/repo return the SBOM available from the GitHub Dependency Graph.

  This function downloads the SPDX SBOM in JSON format from GitHub and
  uses the SPDX tools-java library to convert it into RDF.

  If there are any issues in the underlying BOM during translation
  there may be problems.
  
  Requires a personal access token with public read-only permissions."
  [owner repo & {:keys [pat] :or {pat (System/getenv "GITHUB_TOKEN")}}]
  (let [{:keys [body]} (http/get (format "https://api.github.com/repos/%s/%s/dependency-graph/sbom" owner repo)
                                 {:oauth-token pat
                                  :as          :json-string-keys})
        in             (java.io.File/createTempFile (format "%s-%s" owner repo) ".json")
        out            (str/replace (str in) #".json$" ".rdf")
        clean          (walk/prewalk (fn [form]
                                       form
                                       (if (map-entry? form)
                                         (let [[k v] form]
                                           [k (case k
                                                "licenseConcluded"
                                                (if (or (contains? license-ids v)
                                                        (re-find #"\s+(AND|OR|WITH)\s+" v))
                                                  v
                                                  (match-spdx-license v))
                                                v)])
                                         form))
                                     (get body "sbom"))]
    (spit in (json/write-str clean))
    (org.spdx.tools.SpdxConverter/convert (str in) out)
    (let [model (rdf/parse {:dcat/downloadURL out})
          md    (meta model)]
      (with-meta (mapv db/select-attributes model) md))))

(comment
  (d/with (:db (:graph system)) {:tx-data (get-sbom "clojure" "core.async")}))

(comment
  ;; Adapted from SPARQL here:
  ;; https://nullpointerfactory.wordpress.com/2016/09/26/two-dandy-queries-for-spdx/
  (d/q '[:find ?package ?relationshipType ?name
         :in $
         :where
         [?package :spdx/relationship ?relationship]
         [?relationship :spdx/relationshipType ?relationshipType]
         [?relationship :spdx/relatedSpdxElement ?relatedElement]
         [?relatedElement :spdx/name ?name]]
       (:db (:graph system)))

  (d/q '[:find ?name ?version
         :in $ ?relationshipType
         :where
         [?package :spdx/relationship ?relationship]
         [?relationship :spdx/relationshipType ?relationshipType]
         [?relationship :spdx/relatedSpdxElement ?relatedElement]
         [?relatedElement :spdx/name ?name]
         [(get-else $ ?relatedElement :spdx/versionInfo :spdx/none) ?version]]
       (:db (:graph system))
       :spdx/relationshipType_dependsOn))

(comment
  (d/q '[:find ?e
         :where [?e :spdx/licenseConcluded [:spdx/licenseId "GPL-2.0-only"]]]
       (:db (:graph system)))
  
  (set/union (ffirst (d/q '[:find (distinct ?license)
                            :in $
                            :where
                            (or [?e :spdx/licenseDeclared ?license]
                                [?e :spdx/licenseConcluded ?license])
                            [?license :spdx/licenseId _]]
                          (:db (:graph system))))
             (ffirst (d/q '[:find (distinct ?license)
                            :in $
                            :where
                            (or [?e :spdx/licenseDeclared ?licenseSet]
                                [?e :spdx/licenseConcluded ?licenseSet])
                            [?licenseSet :spdx/member ?license]]
                          (:db (:graph system))))))
(comment
  (d/q '[:find ?package-name ?dependency-name ?dependency-version 
         :in $
         :where
         [?document :spdx/relationship ?packageRel]
         [?packageRel :spdx/relatedSpdxElement ?package]
         [?packageRel :spdx/relationshipType :spdx/relationshipType_describes]
         [?package :rdf/type :spdx/Package]
         [?package :spdx/name ?package-name]
         [?package :spdx/relationship ?relationship]
         [?relationship :spdx/relatedSpdxElement ?dependency]
         [?dependency :spdx/name ?dependency-name]
         [?dependency :spdx/versionInfo ?dependency-version]
         [?relationship :spdx/relationshipType :spdx/relationshipType_dependsOn]]
       (:db (:graph system))))

(comment
  ;; Find all elements with a particular license by name
  (->> (set/union (ffirst (d/q '[:find (distinct ?x)
                                 :where
                                 [?license :spdx/name "CyberNeko License"]
                                 [?licenseSet :spdx/member ?license]
                                 [?x :spdx/licenseConcluded ?licenseSet]]
                               (:db (:graph system))))
                  (ffirst (d/q '[:find (distinct ?x)
                                 :where
                                 [?license :spdx/name "CyberNeko License"]
                                 [?x :spdx/licenseConcluded ?licenseSet]]
                               (:db (:graph system)))))
       (d/q '[:find ?name
              :in $ [?x ...]
              :where
              [?x :spdx/name ?name]]
            (:db (:graph system)))))

(comment
  (d/q '[:find (pull ?e [*])
         :where
         [?e :spdx/referenceCategory :spdx/referenceCategory_security]]
       sbom-db))

(comment
  (d/q '[:find ?purl
         :where
         [?e :spdx/referenceCategory :spdx/referenceCategory_packageManager]
         [?e :spdx/referenceType [:rdfa/uri "http://spdx.org/rdf/references/purl"]]
         [?e :spdx/referenceLocator ?purl]]
       sbom-db))

(def schema
  [{:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/referenceLocator,
    :db/valueType   :db.type/string}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/licenseId,
    :db/unique      :db.unique/identity,
    :db/valueType   :db.type/string}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/licenseExceptionId,
    :db/unique      :db.unique/identity,
    :db/valueType   :db.type/string}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/licenseConcluded}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/packageVerificationCodeValue}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/releaseDate}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/example}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/snippetFromFile}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/isWayBackLink}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/licenseComments}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/reviewDate}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/contextualExample}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/licenseExceptionId}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/relatedSpdxElement}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/standardLicenseTemplate}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/timestamp}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/isLive}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/packageFileName}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/copyrightText}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/relationshipType}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/licenseException}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/primaryPackagePurpose}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/exceptionTextHtml}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/annotator}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/licenseExceptionTemplate}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/reviewer}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/specVersion}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/isDeprecatedLicenseId}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/standardLicenseHeaderHtml}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/isValid}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/validUntilDate}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/spdxDocument}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/externalDocumentId}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/standardLicenseHeaderTemplate}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/documentation}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/creationInfo}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/name}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/description}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/licenseText}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/filesAnalyzed}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/noticeText}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/licenseExceptionText}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/summary}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/referenceCategory}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/supplier}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/referenceType}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/referenceLocator}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/isFsfLibre}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/externalReferenceSite}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/order}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/annotationDate}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/licenseId}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/sourceInfo}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/downloadLocation}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/originator}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/url}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/algorithm}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/licenseListVersion}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/licenseDeclared}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/extractedText}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/annotationType}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/match}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/standardLicenseHeader}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/versionInfo}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/fileName}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/dataLicense}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/created}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/deprecatedVersion}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/isOsiApproved}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/packageVerificationCode}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/builtDate}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/licenseTextHtml}
   {:db/cardinality :db.cardinality/one,
    :db/ident       :spdx/checksumValue}])

(comment
  ;; schema generated with
  (into [{:db/ident       :spdx/referenceLocator
          :db/cardinality :db.cardinality/one
          :db/valueType   :db.type/string}

         {:db/ident       :spdx/licenseId
          :db/cardinality :db.cardinality/one
          :db/valueType   :db.type/string
          :db/unique      :db.unique/identity}

         {:db/ident       :spdx/licenseExceptionId
          :db/cardinality :db.cardinality/one
          :db/valueType   :db.type/string
          :db/unique      :db.unique/identity}]
        (remove (fn [{:db/keys [ident]}]
                  (contains? #{:spdx/member :spdx/checksum} ident)))
        (d/q '[:find ?pid ?card
               :keys :db/ident :db/cardinality
               :where
               (or [?e :owl/qualifiedCardinality 1]
                   [?e :owl/maxQualifiedCardinality 1])
               [?e :owl/onProperty ?p]
               [?p :db/ident ?pid]
               [(ground :db.cardinality/one) ?card]
               [(namespace ?pid) ?ns]
               [(= ?ns "spdx")]]
             (:db (:graph system)))))

(doseq [{:db/keys [ident cardinality valueType unique]} schema]
  (when cardinality
    (defmethod rdf/infer-datomic-cardinality ident [_] cardinality))
  (when valueType
    (defmethod rdf/infer-datomic-type ident [_] valueType))
  (when unique
    (defmethod rdf/infer-datomic-unique ident [_] unique)))

(defrecord SbomGraph [init-db boms]
  com/Lifecycle
  (start [this]
    (let [ ;; bootstrap a database with a datomic schema inferred from loaded RDF models
          boot-db    (db/test-bootstrap init-db)
          ;; install the SPDX License data into the database
          license-db (reduce (fn [with-db tx-data]
                               (:db-after (d/with with-db {:tx-data tx-data})))
                             boot-db
                             (for [file  (file-seq (io/file (io/resource "spdx/license-list-data/")))
                                   :when (.isFile file)
                                   :when (str/ends-with? (.getPath file) ".ttl")]
                               (mapv db/select-attributes (rdf/parse {:dcat/downloadURL (.getPath file)}))))
          ;; for each element of BOM data in `:boms` download and parse RDF from the SPDX SBOM 
          sbom-db    (transduce (map (fn [x]
                                       (if (vector? x)
                                         (let [[owner repo] x]
                                           ;; ensure you have GITHUB_TOKEN exported in your environment
                                           ;; (~/.bashrc etc.)
                                           (get-sbom owner repo))
                                         (rdf/parse x))))
                                (completing
                                  (fn [with-db tx-data]
                                    (try
                                      (:db-after (d/with with-db {:tx-data (mapv db/select-attributes tx-data)}))
                                      (catch Throwable ex
                                        (throw (ex-info (.getMessage ex) {:tx-data tx-data}))))))
                                license-db
                                boms)]
      (assoc this :db sbom-db)))
  (stop [this]
    (doseq [{:db/keys [ident cardinality valueType unique]} schema]
      (when cardinality
        (remove-method rdf/infer-datomic-cardinality ident))
      (when valueType
        (remove-method rdf/infer-datomic-type ident))
      (when unique
        (remove-method rdf/infer-datomic-unique ident)))
    this))

(comment
  (d/q '[:find (pull ?e [:rdfs/_range])
         :where
         [?e :owl/unionOf ?lst]
         [(net.wikipunk.datomic.rl/rdf-list $ ?lst) [?c ...]]
         [?c :db/ident :spdx/AnyLicenseInfo]]
       (:db (:graph system))))
