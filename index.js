const fs = require("fs");

// ___________ BEGIN CONSTANTS __________ //
const COLOR_RESET = "\x1b[0m";
const FG_GREEN = "\x1b[32m";
const FG_RED = "\x1b[31m";
const FG_NEUTRAL = "\x1b[2m"
// ___________ END CONSTANTS __________ //


// MAIN block
const { argv: args } = process;
if (args.length > 2) {
    const operation = args[2];
    switch (operation) {
        case "compare":
        case "c":
            const file1 = args[3];
            const file2 = args[4];
            printVulnerabilitiesSummaryBetweenTwoFiles(file1, file2);
            return;
        default:
            break;
    }
}
args.forEach((arg, index) => {
    if (index > 1) {
        const file = arg;
        printHeader("File: " + file);
        printVulnerabilitiesSummaryFromFile(file);
    }
});

// ___________  FUNCTIONS  ___________ //

// Get dependencies from file
function getDependenciesFromFile(file) {
    const contents = fs.readFileSync(file);
    const jsonContent = JSON.parse(contents);

    return jsonContent.dependencies || [];
}

// ____  BEGIN COLOR MANAGEMENT
function setSuccessConsoleColor() {
    cleanConsoleFormat();
    console.log(FG_GREEN);
}

function setDangerConsoleColor() {
    console.log(FG_RED);
}

function setNeutralConsoleColor() {
    cleanConsoleFormat();
    console.log(FG_NEUTRAL);
}

function printSuccessful(text) {
    printWithColor(FG_GREEN, text);
}

function printDanger(text) {
    printWithColor(FG_RED, text);
}

function printNeutral(text) {
    printWithColor(FG_NEUTRAL, text);
}

function printWithColor(color, text) {
    console.log(color, text, COLOR_RESET);
}

function cleanConsoleFormat() {
    console.log(COLOR_RESET, "");
}
// ____  END COLOR MANAGEMENT

// Get highest vulnerability list from a file
function getVulnerabilitiesSummaryFromFile(file) {
    let vulnerabilitiesSummary = [];
    const dependencies = getDependenciesFromFile(file);
    dependencies.forEach(function(dependency) {
        if (dependency.vulnerabilities) {
            const highestVulnerabilityDetail =  getHighestVulnerabilityDetail(dependency);
            vulnerabilitiesSummary.push(highestVulnerabilityDetail);
        }
    });

    return vulnerabilitiesSummary;
}

// Show analisis from file
function printVulnerabilitiesSummaryFromFile(file) {
    const vulnerabilitiesSummary = getVulnerabilitiesSummaryFromFile(file);
    vulnerabilitiesSummary.forEach(function(vulnerability) {
        printHighestVulnerabilityDetail(vulnerability);
    });

    if (!vulnerabilitiesSummary.length) {
        console.log(FG_NEUTRAL, "\tNo vulnerabilities were found.");
        cleanConsoleFormat();
    }
}

// Show analisis between two files
function printVulnerabilitiesSummaryBetweenTwoFiles(file1, file2) {
    const vulnerabilitiesSummaryFile1 = getVulnerabilitiesSummaryFromFile(file1);
    const vulnerabilitiesSummaryFile2 = getVulnerabilitiesSummaryFromFile(file2);

    setDangerConsoleColor();
    console.log("┌───────────────────────");
    console.log("│  New vulnerabilities found:");
    console.log("└───────────────────────");
    vulnerabilitiesSummaryFile2.forEach(function(vulnerability) {
        if (!existsVulnerabilityInVulnerabilities(vulnerability, vulnerabilitiesSummaryFile1)) {
            printHighestVulnerabilityDetail(vulnerability);
        }
    });

    setSuccessConsoleColor();
    console.log("┌───────────────────────");
    console.log("│  Vulnerabilities corrected:");
    console.log("└───────────────────────");
    vulnerabilitiesSummaryFile1.forEach(function(vulnerability) {
        if (!existsVulnerabilityInVulnerabilities(vulnerability, vulnerabilitiesSummaryFile2)) {
            printHighestVulnerabilityDetail(vulnerability);
        }
    });

    setNeutralConsoleColor();
    console.log("┌───────────────────────");
    console.log("│  Vulnerabilities same state:");
    console.log("└───────────────────────");
    let isThereAny = false;
    vulnerabilitiesSummaryFile1.forEach(function(vulnerability) {
        if (existsVulnerabilityInVulnerabilities(vulnerability, vulnerabilitiesSummaryFile2)) {
            printHighestVulnerabilityDetail(vulnerability);
            isThereAny = true;
        }
    });
    if (!isThereAny) {
        printNeutral(" None.");
    }
}

function existsVulnerabilityInVulnerabilities(vulnerability, vulnerabilities) {
    let existsVulnerability = false;
    vulnerabilities.forEach(function(vul) {
        if (vulnerability.fileName == vul.fileName
            && vulnerability.cveCount == vul.cveCount
            && vulnerability.evidenceCount == vul.evidenceCount
            && vulnerability.highestVulnerability.severity == vul.highestVulnerability.severity
            && vulnerability.highestVulnerability.score == vul.highestVulnerability.score
            && vulnerability.highestVulnerability.source == vul.highestVulnerability.source) {
                existsVulnerability = true;
                return;
            }
    });

    return existsVulnerability;
}

function printHeader(text) {
    setSuccessConsoleColor();
    console.log("┌───────────────────────");
    console.log("│  " + text);
    console.log("└───────────────────────");
    cleanConsoleFormat();
}

/*
    Print vulnerability detail
    Example:
        DEPENDENCY: commons-beanutils-core-1.8.3.jar
        HIGHEST SEVERITY
            Severity:  HIGH
            Score:  7.5
            Source:  NVD
        CVE Count:  2
        EVIDENCE Count: 34
*/
function printHighestVulnerabilityDetail(highestVulnerabilityDetail) {
    const { fileName, highestVulnerability, cveCount, evidenceCount } = highestVulnerabilityDetail;
    const { severity, score, source } = highestVulnerability;

    console.log(`DEPENDENCY:  ${fileName}`);
    console.group("HIGHEST SEVERITY");
    console.log(`Severity:  ${severity}`);
    console.log(`Score:  ${score}`);
    console.log(`Source:  ${source}`);
    console.groupEnd();

    console.log(`CVE Count:  ${cveCount}`);
    console.log(`EVIDENCE Count: ${evidenceCount}`);
    console.log();
}

// Search the highest vulnerability
function getHighestVulnerability({ vulnerabilities }) {

    let highestCvssScoreVulnerability = {
        score: null
    };

    vulnerabilities.forEach((vulnerability, index) => {
        /*
            Priorities:
                1: CVSS V3
                2: CVSS V2
                3: search cvssScore in not NPM sources
                4: search NPM sources
            Known ignoring:
                - Weird case (severity == "0.0" and not key "source", instead "dwsdwource")
        */
        if (vulnerability.cvssv3) {
            const { cvssv3: cvssv3Vulnerability } = vulnerability;
            if (highestCvssScoreVulnerability.score < cvssv3Vulnerability.baseScore) {
                highestCvssScoreVulnerability.severity = cvssv3Vulnerability.baseSeverity;
                highestCvssScoreVulnerability.score = cvssv3Vulnerability.baseScore;
            }
        } else if (vulnerability.cvssv2) {
            const { cvssv2: cvssv2Vulnerability } = vulnerability;
            if (highestCvssScoreVulnerability.score < cvssv2Vulnerability.score) {
                highestCvssScoreVulnerability.severity = cvssv2Vulnerability.severity;
                highestCvssScoreVulnerability.score = cvssv2Vulnerability.score;
            }
        } else if (vulnerability.cvssScore) {
            if (vulnerability.cvssScore > highestCvssScoreVulnerability.score) {
                highestCvssScoreVulnerability.severity = vulnerability.severity;
                highestCvssScoreVulnerability.score = vulnerability.score;
            }
        } else if (vulnerability.source && vulnerability.source.toLowerCase() == "npm") {
            highestCvssScoreVulnerability.severity = vulnerability.severity;
            highestCvssScoreVulnerability.score = -10;
        } else {
            return;
        } 

        highestCvssScoreVulnerability.source = vulnerability.source || vulnerability.dwsdwource;
    });

    return highestCvssScoreVulnerability;
}

/*
    Get the highest vulnerability detail from a dependency
    Example:
        {
            highestVulnerability: {
                severity: "HIGH",
                score:  7.5,
                Source:  NVD
            },
            cveCount: 2,
            evidenceCount: 34
        }
*/
function getHighestVulnerabilityDetail(dependency) {
    const highestVulnerability = getHighestVulnerability(dependency);
    const { fileName, vulnerabilities, evidenceCollected } = dependency;

    const { vendorEvidence, productEvidence, versionEvidence } = evidenceCollected;
    const evidenceCount = vendorEvidence.length +  productEvidence.length + versionEvidence.length;

    return {
        fileName,
        highestVulnerability,
        cveCount: vulnerabilities.length,
        evidenceCount
    }
}