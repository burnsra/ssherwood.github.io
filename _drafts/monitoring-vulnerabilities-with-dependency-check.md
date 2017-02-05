---
layout: post
title:  "Active Monitoring for Security Vulnerabilities in Third-party Libraries using Dependency Check"
date:   2017-01-29 14:11:58 -0500
categories: security sdd owasp
---


An important part of keeping any software project healthy is by monitoring included third-party
libraries and keeping them up to date.  Unfortunately, it can be easy to fall behind and not realize
that one or more of those libraries has been impacted by a potentially serious security
vulnerability.

In many cases, it's likely that the library's author(s) have been notified and already fixed the
underlying issue and even released a new version, but how would your development teams know without
spending countless hours combing through bug reports and various release notes?

In 2013, the [OWASP](https://www.owasp.org/) organization identified this scenario as a
["Top 10" threat](https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities).

Thanks to the volunteer work of dedicated people like Jeremy Long, there is now an open source
utility available called [Dependency Check](https://www.owasp.org/index.php/OWASP_Dependency_Check)
that your teams can start using right away.
  
This brief article will walk through the process of including it in your existing build and help
with evaluating the resulting reports.

# Basic Terminology

It helps to become familiar with some of the common terminology that Dependency Check uses because
you will see them used quite frequently here and in other security-related articles:

* [CPE](https://cpe.mitre.org/): _Common Platform Enumeration_ - a common standard identifier used for all types of software packages including third-party libraries
* [CVE](https://www.cve.mitre.org/): _Common Vulnerability and Exposure_ - a one to many mapping of Common Platform Enumerations to publicly known cybersecurity vulnerabilities
* [NVD](https://nvd.nist.gov/): _National Vulnerability Database_ - a national database of Common Vulnerability and Exposure reports that are provided free to the public
* [CVSS](https://www.first.org/cvss): _Common Vulnerability Scoring System_ - a standardized scoring system for IT vulnerabilities that help indicate urgency of response 
* [CWE](https://cwe.mitre.org/): _Common Weakness Enumeration_ - a catalog of standardized terms for types of software weaknesses and vulnerabilities

# How Does Dependency Check Work?

_Dependency Check_ works via command line or build plugin (Maven, Gradle or even Jenkins) with
primary support for the Java and .NET programming languages.  Additionally, the utility has
experimental support for Ruby, Node.js, Python and C/C++.  The configuration and set-up for the
experimental languages is outside the scope of this article, but many of the same terms and analysis
should apply.

When run, the Dependency Check tool searches through the project's packaged libraries and
transitive  dependencies attempting to match them to Common Platform Enumerations (CPEs).  It uses several
different analyzers to try to match each artifact to a CPE and once a match is found, it uses these
final results as evidence that a specific CPE is indeed valid.

_Dependency Check_ then attempts to identify any Common Vulnerability and Exposures (CVEs) that are
known for the matched CPEs using the National Vulnerability Database (NVD).  Dependency Check will
automatically refresh and cache the NVD data feed each week (only requesting deltas after the
initial download).  Finally, the tool will generate an HTML report with a summary of its findings.

Using the Dependency Check report you can determine what, if any, vulnerabilities exist and evaluate
if they are an active threat to your project.  Like many automatic scanning tools, Dependency Check
can generate false positives.  Ultimately, it is up to you to determine if any specific CPE or CVE
is valid.

If you do determine that a reported vulnerability is not applicable, you can record a exception in a
suppression configuration file and Dependency Check will no longer report them.  In theory, your
team can keep these exceptions up to date and then only be notified when a new vulnerability is
discovered and made available in the NVD.

Ultimately, having Dependency Check integrated into your CI/CD pipeline can help you identify
vulnerabilities as soon as they become available to the public in the NVD.  Hopefully your team can
use this information to reduce the risk of a vulnerability from actually affecting your customers.

# Adding Dependency Check to Your Builds

Assuming you are using either Maven or Gradle for dependency management, it is easy to add the
Dependency Check plugin to your project.

In the Maven POM, add the following plugin definition to the plugins section:

```xml
      <plugin>
        <groupId>org.owasp</groupId>
        <artifactId>dependency-check-maven</artifactId>
        <version>1.4.4.1</version>
        <executions>
          <execution>
            <goals>
              <goal>check</goal>
            </goals>
          </execution>
        </executions>
      </plugin>
```

Maven allows custom plugins to attach and execute at defined phases of any build via goals.  In this
specific case, we have configured Maven to executed the check goal of the plugin which in turn uses
the default phase of Verify (the second to last phase of a full Maven build).

If you don't want to wait for a complete build, you can trigger the report generation by executing
the plugin directly via <plugin-name>:<goal> as exampled:

```bash
mvn dependency-check:check
```

The report will be generated in the target folder and be called `dependency-check-report.html`.  If
you open the resulting report in your browser, you'll see a something like this at the top:

![alt text](images/screen-dependency-check-report-top.png "Report Summary")

In this run, Dependency Check identified 3 vulnerabilities from a generic Spring Boot
application that I recently generated (specifically, version 1.4.3 from [Spring Initializr](http://start.spring.io/)).
Lets take a closer look at each reported item to see how it was identified and if it actually poses
a legitimate threat.

# Don't Panic!

Looking specifically at `CVE-2016-9878`, we can see that it is flagged a a Medium severity
vulnerability.
  
![alt text](images/screen-dependency-check-cve-2016-9878.png "CVE-2016-9878 Summary")

Following the CONFIRM link provided in the report, we find that Pivotal has it documented as a
vulnerability that "exposes a directory traversal attack".  That might be something that we should
be concerned about.
  
However, after looking a bit deeper into the report, it appears to be specifically for CPEs that
involve the core Spring Framework and not Spring Boot itself.  After reviewing the Maven dependency
hierarchy in the IDE we can see that Spring Boot is indeed including some core Spring Framework
libraries, but they are version 4.3.5.  According to the CVE and Pivotal's [web site](https://pivotal.io/security/cve-2016-9878),
the vulnerability was fixed in that version.

So why is Dependency Check warning us about the Spring Boot dependency?

This is a type of false positive caused by matching several (but not all) of the qualities of the
Spring Boot dependency.  Based on that evidence, Dependency Check thinks that the Spring Boot
artifact is the Spring Framework.  It is probable that Boot's version 1.4.3 is partially to blame
for the false match as it appears older than the fixed Spring Framework version.  This is a
situation where we might want to add a suppression.

Side note: during the research for this blog, I discovered that this was actually a known [bug](https://github.com/jeremylong/DependencyCheck/issues/642)
in Dependency Check and has been fixed in the 1.4.5 version.  I've left this information here as an
indicator to the types of false positives that might occur.

In the project create a `dependency-check-suppressions.xml` file and add the following details:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://www.owasp.org/index.php/OWASP_Dependency_Check_Suppression">
  <suppress>
    <notes><![CDATA[
   file name: spring-boot-1.4.3.RELEASE.jar
   Known false positive: https://github.com/jeremylong/DependencyCheck/issues/642
   This can be safely removed after next release of Dependency Check > 1.4.4.1
   ]]></notes>
    <gav regex="true">^org\.springframework\.boot:spring-boot:.*$</gav>
    <cve>CVE-2016-9878</cve>
  </suppress>
</suppressions>
```

We also have to configure the location of the suppression file in the Maven plugin for it to take
effect (for some reason the plugin does not support a default location, so you always have to supply
it):

```xml
<configuration>
  <suppressionFile>${basedir}/dependency-check-suppressions.xml</suppressionFile>
</configuration>
```

Then, when we re-run the plugin, the specific issue is no longer part of the report output.

# Yet Another False Positive?

The next issue we encounter is `CVE-2016-6652`.  It appears to be similar to the previous one in
that it is triggering on a Spring Boot Starter dependency and not on Spring Data JPA itself.  After
reviewing the Maven dependency tree again we can see that Spring Data JPA is version 1.10.6 and that
it is newer than the fixed version, so this is another candidate for suppression for the same
reasons.

Add another suppression entry to the file and re-run the dependency-check task:

```xml
<suppress>
   <notes><![CDATA[
   file name: spring-boot-starter-data-jpa-1.4.3.RELEASE.jar
   Likely false positive matching on the Boot "Starter" instead of actual Data JPA
   ]]></notes>
   <gav regex="true">^org\.springframework\.boot:spring-boot-starter-data-jpa:.*$</gav>
   <cve>CVE-2016-6652</cve>
</suppress>
```

# Should we use "_failBuildOnCVSS_"?

But before we investigate this final CVE issue, we should consider an additional option that can be
configured in the Dependency Check Maven plugin: `failBuildOnCVSS`.  Like its name implies,
Dependency Check can cause a build failure if any CVE exceeds a standard Common Vulnerability
Scoring System (CVSS).  This metric is a value from 0 to 10 that indicates the severity of a
specific vulnerability.  _Wikipedia has a detailed write-up on
how [CVSS](https://en.wikipedia.org/wiki/CVSS) is actually calculated_.

If we are worried about being able to respond quickly to new vulnerabilities, it might make sense to
enable this feature, but at what threshold should it be set?  In my research, typical PCI scanning
requirements indicate a [failure](https://pci.qualys.com/static/help/merchant/network_scans/pci_severity_levels.htm)
is 4.0 or higher.  If you don't have explicit PCI requirements, it might make sense to set it higher
depending on your tolerance to future threats versus failing builds.

```xml
<configuration>
  <!-- typical PCI scanning requirements are to FAIL at CVSS >= 4.0 -->
  <failBuildOnCVSS>4</failBuildOnCVSS>
  <suppressionFile>${basedir}/dependency-check-suppressions.xml</suppressionFile>
</configuration>
```

This does raise a concern about the reproducibility of builds as older builds might not be
considered successful anymore due to more recently discovered vulnerabilities.  To address this
concern it might make sense to configure the Dependency Check plugin as a part of a custom Maven
profile and execute it separately from the main build pipeline.


Links:

- https://cwe.mitre.org/
- https://www.first.org/cvss

