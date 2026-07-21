// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause

// Traductions d'affichage uniquement : le moteur de calcul (cvss40.js) continue de
// travailler avec les libellés anglais d'origine (None/Low/Medium/High/Critical), on
// ne fait que traduire ce qui est montré à l'écran.
const SEVERITY_FR = {
    "None": "Aucune",
    "Low": "Faible",
    "Medium": "Moyenne",
    "High": "Élevée",
    "Critical": "Critique"
};

const BREAKDOWN_LABEL_FR = {
    "Exploitability": "Exploitabilité",
    "Complexity": "Complexité",
    "Vulnerable system": "Système vulnérable",
    "Subsequent system": "Système subséquent",
    "Exploitation": "Exploitation",
    "Security requirements": "Exigences de sécurité"
};

const app = Vue.createApp({
    data() {
        return {
            cvssConfigData: null, // Holds the configuration data loaded from metrics.json
            showDetails: false, // Boolean to control visibility of detailed metric information
            header_height: 0, // Stores the height of the header element, useful for responsive design
            macroVector: null, // Stores the summarized vector representation
            vectorInstance: new Vector(), // Instance of the Vector class to manage CVSS vectors
            cvssInstance: null // Instance of the CVSS40 class to calculate scores and severities
        };
    },
    methods: {
        /**
         * Traduit un libellé de sévérité anglais (calculé par le moteur) vers le français, pour l'affichage.
         * @param {string} severity - Libellé anglais ("Low", "High", etc.)
         * @returns {string} - Libellé en français.
         */
        translateSeverity(severity) {
            return SEVERITY_FR[severity] || severity;
        },
        /**
         * Traduit le nom d'une catégorie du détail du macro-vecteur (ex: "Exploitability" -> "Exploitabilité").
         * @param {string} description - Nom anglais de la catégorie.
         * @returns {string} - Nom en français.
         */
        translateBreakdownLabel(description) {
            return BREAKDOWN_LABEL_FR[description] || description;
        },
        /**
         * Determine la classe CSS de la catégorie de métrique (couleur d'accent) à partir de son nom français.
         * @param {string} metricType - Nom (en français) de la catégorie ("Métriques de Base", etc.).
         * @returns {string} - La classe CSS correspondante ("cat-base", "cat-threat", ...).
         */
        metricTypeClass(metricType) {
            if (metricType.startsWith("Métriques de Base")) return "cat-base";
            if (metricType.startsWith("Métriques de Menace")) return "cat-threat";
            if (metricType.startsWith("Métriques Supplémentaires")) return "cat-supplemental";
            if (metricType.startsWith("Environnementales")) return "cat-env";
            return "cat-base";
        },
        /**
         * Ouvre la boîte de dialogue d'impression du navigateur.
         * La feuille de style @media print n'imprime que le rapport de synthèse.
         */
        printReport() {
            window.print();
        },
        /**
         * Fetches and loads the configuration data from the metrics.json file.
         * Initializes the vector and CVSS instances after loading the data.
         */
        async loadConfigData() {
            try {
                const response = await fetch('./metrics.json');
                this.cvssConfigData = await response.json();
                this.resetSelected(); // Reset vector instance to default state
                this.updateCVSSInstance(); // Initialize CVSS instance with default data
            } catch (error) {
                console.error("Failed to load configuration data:", error);
            }
        },
        /**
         * Generates CSS classes for buttons based on their properties.
         * @param {boolean} isPrimary - Determines if the button is styled as primary.
         * @param {boolean} big - Optional. Determines if the button is large.
         * @returns {string} - The generated CSS class string.
         */
        buttonClass(isPrimary, big = false) {
            return `btn btn-m ${isPrimary ? "btn-primary" : ""} ${!big ? "btn-sm" : ""}`;
        },
        /**
         * Returns the CSS class based on the severity rating.
         * Maps severity levels to appropriate CSS classes for the glowing score badge.
         * @param {string} severityRating - The severity rating (e.g., "Low", "Medium").
         * @returns {string} - The corresponding CSS class.
         */
        getSeverityClass(severityRating) {
            const severityClasses = {
                "None": "sev-none",
                "Low": "sev-low",
                "Medium": "sev-medium",
                "High": "sev-high",
                "Critical": "sev-critical"
            };
            return severityClasses[severityRating] || "sev-none"; // Default to gray if undefined
        },
        /**
         * Copies the current CVSS vector string to the clipboard and updates the URL hash.
         */
        copyVector() {
            navigator.clipboard.writeText(this.vector); // Copy vector to clipboard
            window.location.hash = this.vector; // Update URL hash with the vector
        },
        /**
         * Handles metric updates triggered by button clicks.
         * Updates the Vector instance and refreshes the CVSS instance and URL.
         * @param {string} metric - The metric being updated.
         * @param {string} value - The new value for the metric.
         */
        onButton(metric, value) {
            this.vectorInstance.updateMetric(metric, value); // Update metric in the vector instance
            window.location.hash = this.vector; // Update URL hash
            this.updateCVSSInstance();
        },
        /**
         * Updates the button states based on the provided vector string.
         * Also refreshes the CVSS instance to reflect the new vector state.
         * @param {string} vector - The CVSS vector string to set.
         */
        setButtonsToVector(vector) {
            try {
                this.vectorInstance.updateMetricsFromVectorString(vector);
                this.updateCVSSInstance();
            } catch (error) {
                console.error("Error updating vector:", error.message);
            }
        },
        /**
         * Initializes or updates the CVSS instance based on the current vector.
         * Also updates the macro vector representation.
         */
        updateCVSSInstance() {
            this.cvssInstance = new CVSS40(this.vectorInstance); // Create a new CVSS instance
            this.macroVector = this.vectorInstance.equivalentClasses; // Update macro vector
        },
        /**
         * Resets the vector instance to its default state and clears the URL hash.
         */
        onReset() {
            window.location.hash = ""; // Clear URL hash
            this.resetSelected(); // Reset vector to default state
            this.updateCVSSInstance(); // Refresh CVSS instance
        },
        /**
         * Resets the vector instance to a new default Vector object.
         */
        resetSelected() {
            this.vectorInstance = new Vector();
        },
        /**
         * Splits an object into chunks of a specified size.
         * Useful for dividing data into manageable parts for display.
         * @param {object} object - The object to split.
         * @param {number} chunkSize - The size of each chunk.
         * @returns {array} - An array of chunks, each containing part of the original object.
         */
        splitObjectEntries(object, chunkSize) {
            return Object.entries(object).reduce((result, entry, index) => {
                if (index % chunkSize === 0) result.push([]); // Start a new chunk
                result[result.length - 1].push(entry); // Add entry to the current chunk
                return result;
            }, []);
        }
    },
    computed: {
        /**
         * Computes the current vector string from the Vector instance.
         * @returns {string} - The raw CVSS vector string.
         */
        vector() {
            return this.vectorInstance.raw;
        },
        /**
         * Computes the current CVSS score based on the CVSS instance.
         * @returns {number} - The calculated CVSS score.
         */
        score() {
            return this.cvssInstance ? this.cvssInstance.score : 0;
        },
        /**
         * Computes the current severity rating based on the CVSS instance.
         * @returns {string} - The severity rating (e.g., "Low", "High").
         */
        severityRating() {
            return this.cvssInstance ? this.cvssInstance.severity : "None";
        },
        /**
         * Version française du libellé de sévérité, utilisée uniquement pour l'affichage.
         * getSeverityClass() continue d'utiliser severityRating (en anglais) pour choisir la couleur.
         * @returns {string} - Le libellé de sévérité en français (ex: "Élevée").
         */
        severityRatingFr() {
            return this.translateSeverity(this.severityRating);
        },
        /**
         * Hauteur du graphique de sévérité, en pourcentage (score sur 10).
         * @returns {number} - Pourcentage de remplissage de la barre (0 à 100).
         */
        scorePercent() {
            return Math.max(0, Math.min(100, (Number(this.score) / 10) * 100));
        },
        /**
         * Construit le rapport de synthèse : pour chaque catégorie, la liste des
         * métriques réellement renseignées, avec l'intitulé du choix et son explication.
         * Les métriques laissées sur « Non Défini (X) » sont ignorées (elles n'influent pas
         * sur le score et n'ont pas à figurer dans le rapport).
         * @returns {Array} - Liste de catégories, chacune avec ses lignes de rapport.
         */
        reportGroups() {
            // On lit this.vector pour que le rapport se recalcule à chaque changement de vecteur.
            const anchor = this.vector;
            if (!this.cvssConfigData) return [];

            const groups = [];
            for (const [metricType, typeData] of Object.entries(this.cvssConfigData)) {
                const items = [];
                for (const groupData of Object.values(typeData.metric_groups)) {
                    for (const [metricName, metricData] of Object.entries(groupData)) {
                        const short = metricData.short;
                        const value = this.vectorInstance.metrics[short];
                        if (value === undefined || value === "X") continue; // non renseigné

                        // Retrouver l'option choisie pour récupérer son libellé + explication
                        let chosen = null;
                        for (const [optLabel, optData] of Object.entries(metricData.options)) {
                            if (optLabel === "") continue;
                            if (optData.value === value) {
                                chosen = { label: optLabel, tooltip: optData.tooltip };
                                break;
                            }
                        }
                        if (!chosen) continue;

                        items.push({
                            metricName: metricName,       // ex: "Vecteur d'Attaque (AV)"
                            short: short,                 // ex: "AV"
                            value: value,                 // ex: "N"
                            optionLabel: chosen.label,    // ex: "Réseau (N)"
                            explanation: chosen.tooltip   // phrase explicative + exemple
                        });
                    }
                }
                if (items.length) {
                    groups.push({ metricType: metricType, items: items });
                }
            }
            return groups;
        }
    },
    async beforeMount() {
        await this.loadConfigData();
        this.setButtonsToVector(window.location.hash.slice(1));
    },
    mounted() {
        // Listen for URL hash changes and update the vector accordingly
        window.addEventListener("hashchange", () => {
            this.setButtonsToVector(window.location.hash.slice(1));
        });

        // Setup a resize observer to track changes in the header's height
        const headerElement = document.getElementById('header');
        if (headerElement) {
            const resizeObserver = new ResizeObserver(() => {
                this.header_height = headerElement.clientHeight;
            });
            resizeObserver.observe(headerElement);
        } else {
            console.error("Header element not found");
        }
    }
});

app.mount("#app");

