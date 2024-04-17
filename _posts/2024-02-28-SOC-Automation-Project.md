---
title: Wazuh + SOAR Implementation
description: My very first project! Creating a makeshift SOC featuring SIEM, SOAR and case management.
date: 2024-02-28 18:45:00 +1000
categories: [Projects,Homelab]
tags: [wazuh,soar,homelab]
author: Me
image: assets/img/project1.svg
---

# **Project objective**

* Spin up WAZUH and have at least one agent checking in
* Integrate SOAR for basic automation

## **Introduction**

The aim of this project is to develop from scratch a fully integrated Security Orchestration, Automation, and Response (SOAR) solution incorporating Wazuh for intrusion detection & incident response coupled with TheHive for case management. Additionally, the goal is to create incident response efficiency through effective automated responses with robust logging. Inspiration for this project comes from my curiosity to learn about security operations and wanting to develop my skills in developing and integrating different security tools.

### Main software to be used

**Wazuh**
: Wazuh is an open-source SIEM (Security Information Event Management) system that is used to collect, analyze, aggregate, index, and analyze security-related data which is used to detect intrusions, attacks, vulnerabilities, and malicious activity. It will be the core intrusion detection system in this project as we monitor security events.


**TheHive**
: Another open source platform, it's a 4-in-1 security incident response platform featuring case management, automation, and collaboration tools in addition to threat intelligence support. We'll be using this for our case management system.

**Shuffle**
: This will be our SOAR platform to build security workflows and receive alerts, check malware reputation score with VirusTotal and send alert emails.

### Mapping out our lab logically

Visual diagram for the logical implementation of this lab. This will be our visual guide for setting up and configuring the lab, and how data might flow through each component so we can achieve efficient and automated incident response for this project.
![Diagram](assets/img/diagram.png)

## **Getting started**

### Installing Windows virtual machine

We will need a Windows 10/11 VM to simulate the client environment. Personally, I used Oracle VM VirtualBox for my virtualisation software. There are many online tutorials that show how to setup and create one such as this <a href="https://www.extremetech.com/computing/198427-how-to-install-windows-10-in-a-virtual-machine" target="_blank">article</a> for Windows 10 and this YouTube video for Windows 11:

<iframe width="560" height="315" src="https://www.youtube.com/embed/CNFxFdMT7Kg?si=KImZd41vutNS9pGC" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

<br>

The specifications of the VM I've made are shown down below, I'll be using this VM for the duration of the project.

![PCspecs](assets/img/windows10vmspecs.png)

###  Installing sysmon with sysmonconfig

Sysmon is a Windows system service and device driver that provides detailed information about process creations, network connections, file changes, registry modifications, and more. Sysmon logs will be ingested into the SIEM system so malicious activity can be identified. We'll be using 
<a href="https://github.com/olafhartong/sysmon-modular" target="_blank">sysmon-modular</a>, a sysmon configuration that extends its functionality to monitor and log more comprehensively.

Once sysmon is extracted, and our <a href="https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" target="_blank">sysmonconfig.xml</a> is saved into the same directory as sysmon. We can open up a Powershell terminal inside the directory and install our config using:

```powershell
.\Sysmon64.exe -i .\sysmonconfig.xml
```

To verify that we now have Sysmon installed on our client PC, open Event Viewer and go to Applications and Services Log > Microsoft > Windows, and look for the Sysmon folder.

###  Creating Wazuh and TheHive servers

I'll be using DigitalOcean as my cloud provider, but any other cloud provider will be optimal too. DigitalOcean calls its cloud servers "droplets" and we will need to create 2 droplets, one for Wazuh and one for TheHive. Both droplets will have these specifications:

* 8 GB Memory
* 2 Intel vCPUs
* 160 GB Disk
* Region: Where you currently reside (In my case, Australia/Sydney)
* Operating System: Ubuntu 22.04 (LTS) x64

![droplets](assets/img/droplets.png)

In addition, I will be creating a firewall to be used for both servers to restrict all incoming traffic on TCP and UDP, and only allow requests from my IP address. Outbound rules will be left on default. This measure is to safeguard our servers from unauthorised access attempts by intruders or any automated bots or scanners traversing the Internet hitting our server and trying to break in.
![firewall](assets/img/firewall.png)

![dropletswithfirewall](assets/img/firewall+droplets.png)

### Installing Wazuh and TheHive 

This step consists primarily of using bash commands to handle the installation of both Wazuh and TheHive. The first step is to connect to our Wazuh server through SSH, I'll be using PuTTY to connect to the server from my host machine. 

> You won't be able to launch the Droplet console (found in the access tab) to achieve the same task as we configured our droplets to only accept connections from our IP address. Instead, install a ssh client on your host machine (such as PuTTY) and connect from there.
{: .prompt-warning }

Once we're connected to our wazuh server, we can begin to update the Ubuntu system using:

```bash
apt-get update && apt-get upgrade -y 
```
Then installing Wazuh:
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Once installation is finished, Wazuh will give you a default username and password so you can login into the web interface. Take note of these credentials, then copy and paste the IP address into the web browser of your choice. The Wazuh dashboard will greet you with the login screen and you'll be able to access all its features from there.

```
- To access Wazuh:
https://ipaddress 
```

<br>

Now that Wazuh is installed onto the Wazuh server, it's time to install TheHive on our TheHive server. After we've connected to the TheHive server through SSH, we must install a few dependencies.
```bash
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
```

Then install java:
```bash
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

Then Cassandra:
```bash
wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```

Then ElasticSearch:
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```

Then finally, TheHive:
```bash
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
```

### Configuring TheHive for use

The first step is to connect to TheHive server and configure Cassandra (used for TheHive's database) to work with TheHive, this includes changing its listening, RPC, and seed address to TheHive server IP address, as well as the cluster name (optional but recommended). 

```bash
nano /etc/cassandra/cassandra.yaml # Command to edit cassandra config file
```
![nanosc](assets/img/nanosc.png)

Then remove old files using that default installation of Cassandra left, start the service, and check if it's running: 
```bash
rm -rf /var/lib/cassandra/*
systemctl start cassandra.service
systemctl status cassandra.service
```

Next up is to configure Elasticsearch, changing the cluster name, node name, and network host to TheHive IP address, as well as removing the default 2nd node in the 'cluster.initial_master_nodes' field.
```bash
nano /etc/elasticsearch/elasticsearch.yml
```

Then we need to give TheHive ownership to the attachment storage configuration we gave it (Cassandra) so it can write into that directory.

```bash
chown -R thehive:thehive /opt/thp
```

And lastly, modify TheHive's configuration. This includes changing the hostname IP address for both storage and 'index.search' fields, the cluster name to the one we used for Cassandra and application.baseUrl to the public IP of TheHive.

```bash
nano /etc/thehive/application.conf
```

Finally, we can start up TheHive and check if it's running
```bash
systemctl start thehive
systemctl enable thehive
systemctl status thehive
```

### Configuring Wazuh for use

We will begin by heading to our Wazuh dashboard and deploying our first agent (which will be our client PC). We will first select Windows for the package we want to install, then the public IP of Wazuh will be the server address, and lastly, naming our agent. Wazuh will then generate a command for you in step 4, run this command inside PowerShell (with administrative privileges) on the client PC, then, start the agent using the command Wazuh gives you in step 5.

![agent](assets/img/agent.png)

After a few seconds, Wazuh dashboard will show you that you have one active agent. Upon clicking on active agents and then the agent itself, you will be greeted with another dashboard that displays almost everything you would need to know! A few examples include:
* Security events
* Integrity monitoring 
* Vulnerabilities
* Regulatory compliance
* Security policy monitoring

![wazuhdashboard](assets/img/wazuhdashboard.png)

With the configuration of Wazuh and TheHive now completed, we can start putting them to use. Our next step is to create custom alerts based on the telemetry we are provided.

## **Generating telemetry**
### Setting up

Telemetry is the process of collecting, recording, and analysing data from computer systems or networks to understand how they are operating. This data can be system performance metrics, network traffic details, application behavior, security event information and/or user activities. Our next step is to tell Wazuh to ingest the logs sysmon generates.

On our client PC, We'll first need to take note of sysmon's full name. This can be found inside the log properties for sysmon using event viewer.

![channelname](assets/img/channelname.png)

Now we need to add a new local log file source for Wazuh to ingest, which will be sysmon. The <code class="language-plaintext highlighter-rouge">ossec.conf</code> file is the main configuration file for Wazuh and is found at <code class="language-plaintext highlighter-rouge">C:\Program Files (x86)\ossec-agent\ossec.conf</code>. There will already be existing log sources under <code class="language-plaintext highlighter-rouge">&lt;!-- Log analysis --&gt;</code>, but we will be adding sysmon as a new log source under the existing ones, shown below is how this addition would look like:

```xml
<localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
</localfile>
```
{: file='ossec.conf'}

Once that’s done, we can save the file and restart the Wazuh service.

> Restarting the Wazuh service can be accomplished through the Windows Services interface. Search for "Services" in Windows, locate the Wazuh service, right-click on it and select "Restart".
{: .prompt-tip }

<br>

### Using mimikatz

Our next step is to test Wazuh's ability to detect and report anomalies/incidents within the sysmon logs that are generated on our client PC. We can do this by installing straight-up malware, or just using grey-hat tools. For this project, I'll be using a tool called mimikatz, a popular tool by red-teamers that is designed to extract credentials such as passwords, hashes, PIN codes, Kerberos tickets and other sensitive information from Windows-based systems.

Heading back onto our client VM, mimikatz can be installed <a href="https://github.com/gentilkiwi/mimikatz/releases/" target="_blank">here</a> (File name is <code class="language-plaintext highlighter-rouge">mimikatz_trunk.zip</code>). 

> You will need to exclude the downloads folder from Microsoft Defender and disable any browser protection that may be on. Otherwise, mimikatz will get blocked.
{: .prompt-warning }

Then we can proceed to extract mimikatz and run it inside PowerShell.

![mimikatz](assets/img/mimikatz.png)

Now let's head back to our Wazuh dashboard and see how it responded to the execution of mimikatz on our client VM.

We can see that it has indeed responded pretty heavily.

![alerts](assets/img/alerts.png)

Many of the alerts consisted of tactics such as privilege escalation and command and control. Each alert on a basic level contains a timestamp, technique(s), tactic(s), description, level (severity rating), and a Rule ID. However, each alert can be looked into individually to reveal even more fields related to the alert.

![alerts](assets/img/alertdetails.png)

What I found particularly interesting, is when clicking upon the technique hyperlink (T1105). It directs you to MITRE ATT&CK tab, and explains the details of what the technique is, what it does, and how it works. 

![alerts](assets/img/technique.png)

The <a href="https://attack.mitre.org/" target="_blank">MITRE ATT&CK framework</a> is a globally accessible and comprehensive collection of tactics, techniques and procedures (TTPs) that attackers use in the real world. Looking up the Mitre ID (<a href="https://attack.mitre.org/techniques/T1105/" target="_blank">T1105</a>) on MITRE ATT&CK shows a more comprehensive description and examples of real-world usage using the technique.

However, when we try search for mimikatz in the search bar to detect if it was executed. No results show at all. Thats because Wazuh by default only logs when a rule or alert is triggered. 

![noresults](assets/img/noresults.png)

<blockquote class="prompt-info"><p>It is possible to get Wazuh to log everything, this can be done by configuring the ossec.conf file to <code class="language-plaintext highlighter-rouge">&lt;logall&gt;yes&lt;/logall&gt;</code> and <code class="language-plaintext highlighter-rouge">&lt;logall_json&gt;yes&lt;/logall_json&gt;</code>, the rest of the instructions can be found <a href="https://documentation.wazuh.com/current/user-manual/manager/wazuh-archives.html" target="_blank">here.</a> </p></blockquote>

### Creating a custom rule

Let's go ahead and create a custom rule to detect mimikatz! We can do this in Management > Administration > Rules then clicking on "Manage rules files". Searching for sysmon, we are particularly interested in <code class="language-plaintext highlighter-rouge">0800-sysmon_id_1.xml</code> because it contains all Event ID 1 rules (which encompass process creation).

Inside <code class="language-plaintext highlighter-rouge">0800-sysmon_id_1.xml</code>, I'll be copying out one of the built-in sysmon rules to build out the custom rule for mimikatz.

```xml
<!--
  One of the default sysmon Event ID 1 rules
-->
<rule id="92000" level="4">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)\\(c|w)script\.exe</field>
    <options>no_full_log</options>
    <description>Scripting interpreter spawned a new process</description>
    <mitre>
      <id>T1059.005</id>
    </mitre>
</rule>
```

Now we can head to the custom rules file (<code class="language-plaintext highlighter-rouge">local_rules.xml</code>) by pressing on the custom rules button.

![customrules](assets/img/customrules.png)

Inside, we will paste the default sysmon rule we just copied below the rule that's inside the file already. 

```xml
<!-- Local rules -->

<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<!-- Example -->
<group name="local,syslog,sshd,">

<!--
Dec 10 01:02:02 host sshd[1234]: Failed none for root from 1.1.1.1 port 1066 ssh2
-->
<rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
</rule>

<rule id="92000" level="4">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)\\(c|w)script\.exe</field>
    <options>no_full_log</options>
    <description>Scripting interpreter spawned a new process</description>
    <mitre>
    <id>T1059.005</id>
    </mitre>
</rule>

</group>
```
{: file='local_rules.xml'}

Primarily, we will focus on changing these fields:
- ID: Custom rules start from 100,000. As we can see, the previous rule has an ID of 100,001 so we will change our custom rule to 100,002.
- Level: This is the severity rating we want our alert to have, 15 being the highest possible level. For now, we'll just make it 12.
- Field name: Currently it's <code class="language-plaintext highlighter-rouge">win.eventdata.parentImage</code>, which is a good field as it tracks the chain of events in process creation. but I will change it to <code class="language-plaintext highlighter-rouge">win.eventdata.originalFileName</code>. I made this choice because if I were to use something like <code class="language-plaintext highlighter-rouge">win.eventdata.image</code>, a simple file rename would render the whole rule useless.
- Type: This field is written in regex, we will change it to <code class="language-plaintext highlighter-rouge">type="pcre2">(?i)mimikatz\.exe</field></code> so it searches specifically for mimikatz in the original file name.
- Options: We will remove this field because we want all logs.
- Description: This can be anything, I will just use "Mimikatz Detected" for the description.
- Mitre: We'll change this to T1003, the MITRE ID for OS Credential Dumping as mimikatz is a credential dumper.

Now, our custom rule should look like this:
```xml
<rule id="100002" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz Detected</description>
    <mitre>
        <id>T1003</id>
    </mitre>
</rule>
```

Once that's done, we can save the file. Wazuh will tell us to restart the manager so we will do that too.

Before we put this rule to the test, I will rename the mimikatz file to something different, maybe like "mimicats" to see if our custom rule works with the <code class="language-plaintext highlighter-rouge">win.eventdata.originalFileName</code> field. 

Back on our client PC, I'll now run mimicats.exe and see what happens on Wazuh.

![mimicats](assets/img/mimicats.png)

<br>

And hooray! A new alert popped up on our security events dashboard and it's the custom rule we made to detect mimikatz usage. 

![mimikatzdetected](assets/img/mimikatzdetected.png)

As we can see, the alert does show the <code class="language-plaintext highlighter-rouge">win.eventdata.image</code> field to be mimicats.exe. But, the <code class="language-plaintext highlighter-rouge">win.eventdata.originalFileName</code> field shows mimikatz.exe. Ultimately, it was a good decision to use the <code class="language-plaintext highlighter-rouge">win.eventdata.originalFileName</code> field as the rule still triggered even with file rename, which would not have happened if we were to just track the <code class="language-plaintext highlighter-rouge">win.eventdata.image</code> field.

## Integrating Shuffle (SOAR)

Coming soon...