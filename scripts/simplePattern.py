#/usr/bin/python3
import csv
import re
import matplotlib.pyplot as plt
import numpy as np

filename = "scorecard/Benchmark_v1.2_Scorecard_for_OWASP_ZAP_v2.13.0.csv"
outputfilename = "scorecard/Benchmark_v1.2_Scorecard_for_OWASP_ZAP_v2.13.0_patterns.csv"
# Sipmle Testability Patterns
patterns = [
            "request\\.getHeader[s]?\\(\"Benchmark",     # Injection point is header
            "getParameterNames",                         # Injection point is the parameter name
            "sbxyz\\d{5}[^\\S]*?\\.replace",             # Replace last character in the string
            "param\\.substring",                         # Take substring of input
            "Process p =[^\\S]*?r\\.exec\\(cmd \\+ bar", # Execute command directly
            "fos = new java\\.io\\.FileOutputStream",    # Write to file
            "new java\\.io\\.File\\(param\\)",           # Create new file
            "new java\\.io\\.FileOutputStream\\(new java\\.io\\.FileInputStream\\(fileName\\)\\.getFD\\(\\)\\)",
            "new java\\.io\\.File\\([^\\S]*?new java\\.io\\.File\\("
]

d = []
cats = ["xss", "sqli", "cmdi"]

with open(filename, "r", newline='') as csvfile:
    csvreader = csv.DictReader(csvfile)
    for row in csvreader:
        patternsFound = {}
        onePatternFound = False
        name = row["# test name"]
        passed = row[" pass/fail"] == ' pass'
        cat = row[" category"].strip()
        vulnerable = row[" real vulnerability"] == ' true'
        testfile = "src/main/java/org/owasp/benchmark/testcode/" + name + ".java"

        for pattern in patterns:
            patternsFound[pattern] = False
        with open(testfile, "r") as f:
            code = f.read()
            for pattern in patterns:
                if re.search(pattern, code):
                    patternsFound[pattern] = True
                    onePatternFound = True
        row = dict(row.items() | patternsFound.items())
        d.append(row)
        #print(row)
        if cat in cats and vulnerable and not onePatternFound and not passed:
            print(name, "No pattern found!")




passfail = ["total", "pass", "fail", "ratio"]
counts = {}
for status in passfail:
    counts[status] = {}
    for pattern in patterns:
        counts[status][pattern] = {}
        for cat in cats:
            counts[status][pattern][cat] = 0

for row in d:
    cat = row[" category"].strip()
    passed = row[" pass/fail"] == ' pass'
    vulnerable = row[" real vulnerability"] == ' true'
    if (cat in cats) and vulnerable:
        for pattern in patterns:
            if row[pattern]:
                if passed:
                    counts["pass"][pattern][cat] += 1
                else:
                    counts["fail"][pattern][cat] += 1
                counts["total"][pattern][cat] += 1

for cat in cats:
    for pattern in patterns:
        if counts["total"][pattern][cat] > 0:
            counts["ratio"][pattern][cat] = float(counts["fail"][pattern][cat]) / float(counts["total"][pattern][cat])

def subcategorybar(X, vals, labels, width=0.75):
    n = len(vals)
    _X = np.arange(len(X))
    plt.figure(figsize=(10,6))
    for i in range(n):
        label = labels[i][0:5]
        plt.bar(_X - width/2. + i/float(n)*width, vals[i],
                width=width/float(n), align="edge", label=label)
    plt.legend(loc="upper right")
    ticks = [x[0:20] for x in X]
    plt.xticks(_X, ticks)
    plt.xticks(rotation=90)
    plt.tight_layout()


for status in passfail:
    Y = []
    for cat in cats:
        y = []
        for pattern in patterns:
            y.append(counts[status][pattern][cat])
        Y.append(y)
    subcategorybar(patterns, Y, cats)
    plt.savefig("myplot_" + status + ".png")

with open(outputfilename, 'w', newline='') as csvfile:
    fieldnames = row.keys()
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for row in d:
        writer.writerow(row)
