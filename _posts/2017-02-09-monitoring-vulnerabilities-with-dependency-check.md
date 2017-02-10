---
layout: post
title:  "Active Monitoring for Security Vulnerabilities in Third-party Libraries using Dependency Check"
date:   2017-02-09 17:37:58 -0500
categories: security sdd owasp
---

An important part of keeping any software project healthy is by monitoring included third-party
libraries and keeping them up to date.  Unfortunately, it can be easy to fall behind and not realize
that one or more of those libraries has been impacted by a potentially serious security
vulnerability.

In many cases, it's likely that the library's author(s) have already been notified and have fixed
the underlying issue and even released a new version, but how would your development teams know
without spending countless hours combing through bug reports and various release notes?  In 2013,
the [OWASP](https://www.owasp.org/) organization identified this scenario as a
["Top 10" threat](https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities).

Thanks to the volunteer work of dedicated people like Jeremy Long, there is now an open source
utility available called [Dependency Check](https://www.owasp.org/index.php/OWASP_Dependency_Check)
that your teams can start using right away.
  
This brief article will walk through the process of including it in your existing build and help
with reading and evaluating the report results.

# Basic Terminology

It helps to become familiar with some of the common terminology that Dependency Check uses because
they are used quite frequently in the [documentation](https://jeremylong.github.io/DependencyCheck/)
and other security-related articles:

* [NVD](https://nvd.nist.gov/): _National Vulnerability Database_ - a national database of Common Vulnerability and Exposure reports that are provided free to the public
* [CVE](https://www.cve.mitre.org/): _Common Vulnerability and Exposure_ - a one to many mapping of Common Platform Enumerations to publicly known cybersecurity vulnerabilities
* [CPE](https://cpe.mitre.org/): _Common Platform Enumeration_ - a common standard identifier used for all types of software packages including third-party libraries
* [CWE](https://cwe.mitre.org/): _Common Weakness Enumeration_ - a catalog of standardized terms for types of software weaknesses and vulnerabilities
* [CVSS](https://www.first.org/cvss): _Common Vulnerability Scoring System_ - a standardized scoring system for IT vulnerabilities that help indicate urgency of response 

# How Does Dependency Check Work?

Dependency Check works via command line tooling or build plugin (Maven, Gradle or even Jenkins)
with primary support for the Java and .NET programming languages.  Additionally, the utility has
experimental support for Ruby, Node.js, Python and C/C++.  The configuration and set-up for the
experimental languages is outside the scope of this article, but many of the same terms and analysis
should apply.

When run, the Dependency Check tool searches through the project's packaged libraries and
transitive  dependencies attempting to match them to Common Platform Enumerations (CPEs).  It uses
several different analyzers to try to match each artifact to a CPE and once a match is found, it
uses these results as final evidence that a specific CPE is indeed valid.

Dependency Check then attempts to identify any Common Vulnerability and Exposures (CVEs) that are
known for the matched CPEs using the National Vulnerability Database (NVD).  Dependency Check will
automatically refresh and cache the NVD data feed each week (only requesting deltas after the
initial download).  Finally, the tool will generate an HTML report with a summary of its findings.

Using the Dependency Check report you can determine what, if any, vulnerabilities exist and evaluate
if they are an active threat to your project.  Like many automatic scanning tools, Dependency Check
can generate false positives.  Ultimately, it is up to you to determine if any specific CPE or CVE
is valid.

If you do determine that a reported vulnerability is not applicable to your project, you can record
a exception in a suppression configuration file and Dependency Check will no longer report them.  In
theory, your team can keep these exceptions up to date and then only be notified when a new
vulnerability is discovered and made available in the NVD.

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

Looking specifically at [`CVE-2016-9878`](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-9878),
we can see that it is flagged a a Medium severity vulnerability.
  
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

# Another False Positive?

The next issue we encounter is [`CVE-2016-6652`](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-6652).
It appears to be similar to the previous one in that it is triggering on a Spring Boot Starter
dependency and not on Spring Data JPA itself.  After reviewing the Maven dependency tree again we
can see that Spring Data JPA is version 1.10.6 and that it is newer than the reported fixed version.
This is another candidate for suppression for similar reasons as `CVE-2016-9878`.

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

But before we investigate this final CVEs, let's consider an additional option that can be
configured on the Dependency Check Maven plugin: `failBuildOnCVSS`.  Like its name implies,
Dependency Check can cause a build failure if any CVE exceeds a standard Common Vulnerability
Scoring System (CVSS) threshold.
  
CVSS is a calculated value from 0 to 10 that indicates the severity of a specific vulnerability
(with 10 being the most severe).  _Wikipedia has a detailed write-up on how
[CVSS](https://en.wikipedia.org/wiki/CVSS) is actually determined_.

If we are concerned about being able to respond quickly to new vulnerabilities, it might make sense
to enable this feature, but at what level should it be set?
  
Typical PCI scanning requirements indicate that a CVSS score as low as 4.0 can be a [failure](https://pci.qualys.com/static/help/merchant/network_scans/pci_severity_levels.htm).
If you don't have explicit PCI requirements, it might make sense to set it higher depending on your
tolerance to future threats versus breaking a build pipeline.

To enable this feature, modify the plugin configuration block:

```xml
<configuration>
  <!-- typical PCI scanning requirements are to FAIL at CVSS >= 4.0 -->
  <failBuildOnCVSS>4</failBuildOnCVSS>
  <suppressionFile>${basedir}/dependency-check-suppressions.xml</suppressionFile>
</configuration>
```

This additional configuration does raise the concern about risk to the reproducibility of builds --
older builds might not succeed anymore due to recently discovered vulnerabilities.  To address this
concern consider making the Dependency Check plugin part of a custom [Maven profile](https://maven.apache.org/guides/introduction/introduction-to-profiles.html)
and separate the execution from the main build pipeline.

# The Final CVEs

The last CVEs detected are interesting ones that might really apply depending on your environment.
With [`CVE-2016-6325`](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-6325) and [`CVE-2016-5425`](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-5425)
both vulnerabilities are specific to Tomcat packaging on Red Hat Enterprise Linux (RHE).  The
vulnerabilities potentially allow local users to gain elevated privileges by leveraging membership
in the tomcat group.  The CVSS for both of these CVEs is 7.2 and have a High severity.

Luckily, I use the embedded Tomcat approach (executable JAR) and don't rely on any Tomcat packaging
or local configuration files.  While this vulnerability is curious, it is not applicable and can be
suppressed from future runs.

The final suppression entries can be added as follows:

```xml
  <!-- From reading the links provided by these CVEs this exploit is specific to the
  installed Tomcat packages on Linux.  The CPEs reference tomcat-embed-core which is
  a jar (i.e. embedded tomcat) and not part of the vulnerable packaging -->
  <suppress>
    <notes><![CDATA[
   file name: tomcat-embed-core-8.5.11.jar
   info: http://securityaffairs.co/wordpress/52156/hacking/cve-2016-5425-apache-tomcat.html
   ]]></notes>
    <gav regex="true">^org\.apache\.tomcat\.embed:tomcat-embed-.*:.*$</gav>
    <cve>CVE-2016-6325</cve>
    <cve>CVE-2016-5425</cve>
  </suppress>
```

Running the Dependency Check report one last time should yield a clean result and with no build
failures.  Now we can move forward and be more confident with our third-party libraries as well as
have a better understanding of our application's risk exposure.

# Summary

With little effort, it is possible to have a security scan performed on your project's third-party
libraries with each build.  As an open source tool, Dependency Check provides direct access to a
large centralized database of reported vulnerabilities and, by using its build plugins, it can even
interrupt your automated CI/CD pipeline if new issues are identified.

Also, the use of Dependency Check should give your teams valuable time by automatically identifying
potential threats in libraries and hopefully provide links to aid in the remediation of any actual
vulnerabilities as they are identified and made public to the NVD.