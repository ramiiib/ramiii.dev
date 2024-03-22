---
title: Wazuh + SOAR Implementation
date: 2024-02-28 18:45:00 +1000
categories: [Projects,Homelab]
tags: [wazuh,soar,homelab]    
---

# **Project objective**

* Spin up WAZUH and have at least one agent checking in
* Integrate SOAR for basic automation

## **Introduction**

The aim of this project is to develop from scratch a fully integrated Security Orchestration, Automation, and Response (SOAR) solution incorporating Wazuh for intrusion detection & incident response coupled with TheHive for case management. Additionally, the goal is to create incident response efficiency through effective automated responses with robust logging. Inspiration for this project comes from my curiosity to learn about security operations and how numerous computers in organisations are protected from malware.

### What is Wazuh/TheHive/Shuffle?

(to be explained)

### Mapping out our lab logically

Visual diagram for the logical implementation of this lab (to be explained)
![Diagram](assets/lib/img/diagram.png)

## **Getting started**

### Installing Windows 10 vm

This will be our client PC, hosted on an ESXi server.

![PCspecs](assets/lib/img/windows10vmspecs.png)

###  Installing sysmon with sysmonconfig

Sysmon is a Windows system service and device driver that provides detailed information about process creations, network connections, file changes, registry modifications, and more. Sysmon logs will be ingested into the SIEM system so malicious activity can be identified. We'll be using [sysmon-modular](https://github.com/olafhartong/sysmon-modular), a sysmon configuration that extends its functionality to monitor and log more comprehensively.

Once sysmon is extracted, and our [sysmonconfig.xml](https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml) is saved into the same directory as sysmon. We can open up a Powershell terminal inside the directory and install our config using:

```powershell
.\Sysmon64.exe -i .\sysmonconfig.xml
```

![sysmondir](assets/lib/img/sysmon.png)

To verify that we now have Sysmon installed on our client PC, open Event Viewer and go to Applications and Services Log > Microsoft > Windows, and look for the Sysmon folder.

###  Creating Wazuh and TheHive servers

I'll be using DigitalOcean as my cloud provider, but any other cloud provider will be optimal too. DigitalOcean calls its cloud servers "droplets" and we will need to create 2 droplets, one for Wazuh and one for TheHive. Both droplets will have these specifications:

* 8 GB Memory
* 2 Intel vCPUs
* 160 GB Disk
* Region: Where you currently reside (In my case, Australia/Sydney)
* Operating System: Ubuntu 22.04 (LTS) x64

![droplets](assets/lib/img/droplets.png)

In addition, I will be creating a firewall to be used for both servers to restrict all incoming traffic on TCP and UDP, and only allow requests from my IP address. Outbound rules will be left on default. This measure is to safeguard our servers from unauthorised access attempts by intruders or any automated bots or scanners traversing the Internet hitting our server and trying to break in.
![firewall](assets/lib/img/firewall.png)
![dropletswithfirewall](assets/lib/img/firewall+droplets.png)

### Installing Wazuh and TheHive 

This step compromises primarily off bash commands to handle the installation of both Wazuh and TheHive. The first step is to connect to our Wazuh server through SSH, I'll be using PuTTY to connect to the server from my host machine. 

> You won't be able to launch the Droplet console which can be found in the access tab to achieve the same task. Instead, 
{: .prompt-warning }

Once were connected to our wazuh server, we can begin to update the Ubuntu system using:

```bash
apt-get update && apt-get upgrade -y 
```
Then installing Wazuh:
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Once installation is finished, Wazuh will give you a default username and password so you can login into the web interface. Take note of these credentials, then copy and paste the IP address into the web browser of your choice. The Wazuh dashboard will greet you with the login screen and you'll be able to access all its features from there.

```text
https://ipaddress
```
---
---
__________________________________
---
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

The first step is to connect to TheHive server and configure Cassandra (used for TheHive's database) to work with TheHive, this includes changing its listening, RPC, and seed address to thehive server ip address, as well as the cluster name (optional but recommended). 

```bash
nano /etc/cassandra/cassandra.yaml # Command to edit cassandra config file
```
![nanosc](assets/lib/img/nanosc.png)

Then remove old files using that default installation of Cassandra left, start the service, and check if it's running: 
```bash
rm -rf /var/lib/cassandra/*
systemctl start cassandra.service
systemctl status cassandra.service
```

Next up is to configure Elasticsearch, changing the cluster name, node name, and network host to thehive ip address, as well as removing the default 2nd node in cluster.initial_master_nodes.
```bash
nano /etc/elasticsearch/elasticsearch.yml
```

Then we need to give thehive ownership to the attachment storage configuration we gave it (cassandra) so it can write into that directory.

```bash
chown -R thehive:thehive /opt/thp
```

And lastly, configure TheHive's configuration. Which includes changing the hostname IP address for both storage and index.search, the cluster name we used for Cassandra, application.baseUrl to the public ip of TheHive.

```bash
nano /etc/thehive/application.conf
```

Finally, we can start up TheHive and check if its running
```bash
systemctl start thehive
systemctl enable thehive
systemctl status thehive
```

### Configuring Wazuh for use

We will begin by heading to our Wazuh dashboard and deploying our first agent, selecting Windows for the package we want to install (as our client PC is on Windows), the server address will be the public IP of Wazuh, and lastly naming our agent. Wazuh will then generate a command for you in step 4, run this command inside PowerShell (with administrative privileges) on the client PC (our windows 10 vm), then, start the agent using the command Wazuh gives you in step 5.

After a few seconds, Wazuh dashboard will show you that you have one active agent. Upon clicking on active agents and then the agent itself, you will be greeted with another dashboard that displays almost everything you would need to know! Few examples include:
* Security events
* Integrity monitoring 
* Vulnerabilities
* Regulatory compliance
* Security policy monitoring

![wazuhdashboard](assets/lib/img/wazuhdashboard.png)

With the configuration of Wazuh and TheHive now completed, we can start putting them to use. Our next step is to create some telemetry and create an alert related to it.

## **Generating telemetry**
### Setting up

Telemetry monitoring is the process of collecting, recording, and analysing data from systems to understand how they are functioning. Ranging from what kind of traffic is being generated, configuration changes, suspicious behaviors, user activity, and more. Our next step is to tell Wazuh to ingest the logs sysmon generates.

We'll first need to take note of sysmon's full name. This can be found inside event viewer's log properties for sysmon.

![channelname](assets/lib/img/channelname.png)

Then open into the ossec.conf file (as Administrator) and add the location name of sysmons channel name (found in event viewer) in the format below. Once that's done, we can save the file and restart the Wazuh service.

![osseconf](assets/lib/img/ossecconf.png)
> Restarting the Wazuh service can be accomplished through the Windows Services interface. Search for "Services" in Windows, locate the Wazuh service, right-click on it and select "Restart".
{: .prompt-tip }
---
---
__________________________________
---

### Using mimikatz

Our next step is to test Wazuh's ability to detect and report anomalies within the sysmon logs that are generated on our client PC. We can do this by installing straight malware, or just use grey-hat tools. For this project, i'll be using a tool called mimikatz, a popular tool by red-teamers that is designed to extract credentials such as passwords, hashes, PIN codes, kerberos tickets and other sensitive information from Windows-based systems.

Heading back onto our client VM, mimikatz can be installed [here](https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip). 

> You will need to exclude the downloads folder from Microsoft Defender and disable any browser protection that may be on. Otherwise, mimikatz will get blocked.
{: .prompt-warning }

Then we can proceed to extract mimikatz and run it inside PowerShell with admin privileges. 

![mimikatz](assets/lib/img/mimikatz.png)

Now lets head back to our Wazuh dashboard and see how it responded to the execution of mimikatz on our client VM.

