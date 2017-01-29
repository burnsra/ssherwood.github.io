---
layout: post
title:  "Monitoring Security Vulnerabilities in Third-party Libraries using Dependency Check"
date:   2017-01-29 14:11:58 -0500
categories: security sdd
---

An important part of keeping any software project healthy is by monitoring included third-party
libraries and keeping them up to date.  Unfortunately, it can be easy to fall behind and not realize
that one or more of those libraries has been impacted by a serious security vulnerability.

In many cases, it's likely that the library's author(s) have already fixed the underlying issue and
released a new version, but how would you know without spending countless hours combing through bug
reports and various release notes?

In 2013, the OWASP organization identified this common scenario as a ["Top 10" threat](https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities).

Thanks to the volunteer work of dedicated people like Jeremy Long, there is a free utility available
called [Dependency Check](https://www.owasp.org/index.php/OWASP_Dependency_Check) that you can start
using right away.  This article will help walk you through the process of including it in your
existing build and help with evaluating the resulting reports.

# Basic Terminology

It helps to become familiar with some of the terminology that Dependency Check uses because you will
see it used quite frequently in the documentation:

* CPE: Common Platform Enumeration - this is a common standard identifier used for all types of software packages including third-party libraries
* CVE: Common Vulnerability and Exposure - a one to many mapping of Common Platform Enumerations to publicly known cybersecurity vulnerabilities
* NVD: National Vulnerability Database - a national database of Common Vulnerability and Exposure reports that are provided free to the public

# How Does Dependency Check Work?

Dependency Check works via command line or build plugin (Maven, Gradle or Jenkins) with primary
support for Java and .NET.  Additionally, the utility has experimental support for Ruby, Node.js,
Python and C/C++ (configuration and set-up for the experimental languages is outside the scope of
this article).

When run, the Dependency Check tool searches through your project's libraries and transitive
dependencies attempting to match them to CPEs.  Then it attempts to identify any CVEs that are known
for the CPEs using the National Vulnerability Database.  Dependency Check will automatically refresh
and cache the data feed each week from the NVD (requesting deltas as the initial download can take a
while).  Finally, Dependency Check will generate an HTML report with a summary of its findings.

Using the Dependency Check report you can determine what, if any, vulnerabilities actually exist and
evaluate if they are an active threat to your project.  Like many automatic scanning tools,
Dependency Check is not a perfect tool and it may generate false positives.  Ultimately, it is up to
you to determine if any specific CPE and/or CVE is valid.

If you do determine that a reported vulnerability is not applicable, you can record a exception in a
standard suppression file and Dependency Check will no longer flag them.  In theory, you can keep
these exceptions up to date and then only be notified when a new vulnerability is discovered and
made available in the NVD.

Ultimately, having Dependency Check as an automated part of your CI/CD pipeline can help you
identify vulnerabilities as soon as they become available to the public in the NVD.  Hopefully you
can use this information to reduce the risk of a vulnerability from actually affecting your
customers.

# Adding Dependency Check to Your Builds

Assuming you are using Maven or Gradle for dependency management, it is very easy to add a 
Dependency Check plugin to your project.

If using Maven, add the following plugin definition to your `pom.xml` plugins section:

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

Maven allows custom plugins to attach and execute at defined phases of any build.  In this case, we
have configured Maven to executed the check goal of the plugin which happens to use the default
phase of Verify (which is the second to lase phase of any Maven build).

If you don't want to wait, you can trigger the report generation by executing the plugin directly:

```bash
mvn dependency-check:check
```

The report will output in the target folder and be called `dependency-check-report.html`.  If you
open the report in your browser, you'll see a something like this at the top:

![alt text](images/screen-dependency-check-report-top.png "Report Summary")

In this case, the tool identified 3 vulnerabilities from a generic Spring Boot application
that I recently generated (specifically, version 1.4.3 from http://start.spring.io/).
  
Lets take a closer look at each reported item to see how it was identified and if it actually poses
a legitimate threat.

# Don't Panic!

Looking specifically at `CVE-2016-9878`, we can see that it is flagged a a Medium severity
vulnerability.
  
![alt text](images/screen-dependency-check-cve-2016-9878.png "CVE-2016-9878 Summary")

Following the CONFIRM link provided in the report, we find that Pivotal has documented it as a
vulnerability that "exposes a directory traversal attack".  That might be something that we should
be concerned about.  However, after looking a bit deeper into the report, it appears to be
specifically for CPEs that involve the core Spring Framework and not Spring Boot itself.

Reviewing the Maven dependency hierarchy we find that Spring Boot is indeed including some Spring
Framework libraries, but they are version 4.3.5.  According to the CVE and Pivotal's [web site](https://pivotal.io/security/cve-2016-9878),
the specific issue was fixed in this version.  So why is Dependency Check warning us about the
Spring Boot dependency?

This is a false positive caused by the somewhat fuzzy matching logic that Dependency Check does on
the dependency names identified within the project.  Dependency Check records the confidence of each
potential match, some of which are LOW, and triggered the warning.  It is probable that Boot's
version 1.4.3 is partially to blame as it matches a much older Spring Framework version that does
contain the vulnerability.  This is a situation where we might want to add a suppression.

Actually, it is a known [bug](https://github.com/jeremylong/DependencyCheck/issues/642) and is
scheduled to be fixed in the next release.  However, in the interim, we should still create a
suppression file to tell Dependency Check to ignore this match for Spring
Boot until then.

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

For this to suppression to take effect, we also have to configure the location of the suppression
file in the Maven plugin like this:

```xml
        <configuration>
          <suppressionFile>${basedir}/dependency-check-suppressions.xml</suppressionFile>
        </configuration>
```

(For some reason the plugin does not support a default location, so you always have to supply it).
 
Then, when we re-run the plugin, the specific issue is no longer part of the report output.

# Yet Another Suppression?

The next issue we encounter is CVE-2016-6652.  It appears to be similar to the previous one in that
is is triggering on a Spring Boot Starter dependency and not on Spring Data JPA itself.  Reviewing
the Maven dependency tree again we can see that Spring Data JPA is version 1.10.6 and is above the
known fixed version, so this is another candidate for suppression (and this one hasn't been
identified as a bug yet).

Like before, add another suppression to the file and re-run the dependency-check task:

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

