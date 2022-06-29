# CEH-Practical-Notes
Minimalist notes for CEH-practical Cert.

# CEH v11 **Course contents**
- [ ] Module 01: Introduction to Ethical Hacking  
- [ ] Module 02: Footprinting and Reconnaissance [[1 - Footprinting and Recconnaissance]]
- [ ] Module 03: Scanning Networks [[2 - Scanning Networks]]
- [ ] Module 04: Enumeration [[3 - Enumeration]]
- [ ] Module 05: Vulnerability Analysis [[4 - Vulnerability Analysis]]
- [ ] Module 06: System Hacking [[5 - System Hacking]]
- [ ] Module 07: Malware Threats  
- [ ] Module 08: Sniffing  
- [ ] Module 09: Social Engineering  
- [ ] Module 10: Denial-of-Service  
- [ ] Module 11: Session Hijacking  
- [ ] Module 12: Evading IDS, Firewalls, and Honeypots  
- [ ] Module 13: Hacking Web Servers  
- [ ] Module 14: Hacking Web Applications  
- [ ] Module 15: SQL Injection  
- [ ] Module 16: Hacking Wireless Networks  
- [ ] Module 17: Hacking Mobile Platforms  
- [ ] Module 18: IoT Hacking  
- [ ] Module 19: Cloud Computing  
- [ ] Module 20: Cryptography
- [ ] Module 21: Examples [[6 - Examples - CEH - PRACTICAL]]
- [ ] Module 22: Commands - tips - tools [[7 - Commands, Tips, Tools - CEHP]]
- [ ] Module 23: CEH - My methology [[8 - CEH-methology]]

# What is an Ethical Hacker?

The Ethical Hacker is an individual who is usually employed with the organization and who can be trusted to undertake an attempt to penetrate networks and/or computer systems using the same methods as a Hacker. Hacking is a felony in some countries. When it is done by request and under a contract between and Ethical Hacker and an organization, it is legal. The most important point is that an Ethical Hacker has authorization to probe the target.

A Certified Ethical Hacker is a skilled professional who understands and knows how to look for the weaknesses and vulnerabilities in target systems and uses the same knowledge and tools as a malicious hacker.

# What is Information Security?

Information security refers to the protection or safeguarding of information and information systems that use, store, and transmit information from unauthorized access, disclosure, alteration and destruction. Information is a critical asset that organizations must secure. If sensitive information falls into the wrong hands, then the respective organization may suffer huge losses in terms of finances, brand reputation, customers, or in others ways.

## Elements of Information Security

Information security is `the state of the well-being of information and infrastructure in which the possibility of the theft, tampreing, or disruption of information and services is kept low or tolerable.` It relies on five major elements: `confidentiality, integrity, availability, authenticity and non-repudiation.`
- #### Confidentiality.
Confidentiality is the assurance that the information is accessible only to authorized.
- #### Integrity
Integrity is the trustworthiness of data or resources in the prevention of improper and unauthorized changes -  the assurance that information is sufficiently accurate for its purpose.
- #### Availability
Availability is the assurance that the systems responsible for delivering, storing and processing information are accessible when required by authorized users.
- #### Authenticity
Authenticity refers to the characteristic of communication, documents, or any data that ensures the quality of being genuine or uncorrupted. The major role of authentication is to confirm that a user is genuine.
- #### Non-Repudiation
Non-repudiation is a way to guarantee that the sender of a message cannot later deny having sent the message and that the recipient cannot deny having received the message. Individuals and organizations use digital signatures to ensure non-repudiation.

## Classification of Attacks
According to IATF (``Information Assurance Technical Framework``), security attacks are classified into five categories: `passive, active, close-in, insider and distribution`.

- #### Passive Attacks
 	- Passive attacks do not  tamper with the data and involve intercepting and monitoring network traffic and data flow on the target network.
 	- Examples include sniffing and eavesdropping (listen from hidden).
- #### Active Attacks
	- Active attacks tamper with the data in transit or disrupt the communication or services between the systems to bypass or break into secured systems
	- Examples include DoS, Man-in-the-Middle, session hijacking, and SQL injection.
- #### Close-in Attacks
	- Close-in attacks are performed when the attacker is in close physical proximity with the target system or network in order to gather, modify, or disrupt access to information.
	- Examples include social engineering such as eavesdropping, shoulder surfing, and dumpster diving (search in the garbage).
- #### Insider Attacks
	- Insider attacks involve using privileged access to violate rules or intentionally cause a threat to the organization's information or information systems.
	- Examples include theft of physical devices and planting keyloggers, backdoors, and malware.
- #### Distribution Attacks
	- Distribution attacks occur when attackers tamper with hardware or software prior to installation.
	- Examples attackers tamper with the hardware or software at its source or in transit.
	
## Cyber Kill Chain Methodology

The cyber kill chain is an efficient and effective way of illustrating how an adversary can attack the target organization.
#### Methodology:
- #### Reconnaissance:
	Gather data on the target to probe for weak points.
- #### Weaponization:
	Create a deliverable malicious payload using an exploit and a backdoor.
- #### Delivery:
	Send weaponized bundle to the victim using email, USB...
- #### Exploitation:
	Exploit a vulnerability by executing code on the victim's system.
- #### Installation:
	Install malware on the target system.
- #### Command and Control:
	Create a command and control channel to communicate and pass data back and forth.
- #### Actions on Objectives:
	Perform actions to achieve intended objectives and goals.
	
## Tactics, Techniques, and Procedures (TTPs)
The terms `tactics, techniques, and procedures` refer to the patterns of activities and methods associated with specific threat actors or groups of threat actors.

- #### Tactics:
	`Tactics` are the guidelines that describe the `way an attacker advanced persistent threat (APT) performs the attack` from beginning to the end.
- #### Techniques:
	`Techniques` are the `technical methods used by an attacker` to achieve intermediate results during the attack.
- #### Procedures:
	`Procedures` are `organizatonial approaches that threat actors follow` to launch an attack.
	
## Adversary Behavioral Identification
Adversary behavioral identification involves the identification of the common methods or techniques followed by and adversary to launch attacks to penetrate and organization's network.

- #### Internal Reconnaissance
	Once the adversary is inside the target network, they follow various techniques and methods to carry out internal reconnaissance.
- #### Use of PowerShell
	PowerShell can be used by an adversary as a toll for automating data exfiltration and launching further attacks.
- #### Unspecified Proxy Activities
	An adversary can create and configure multiple domains pointing to the same host, thus, allowing an adversary to switch quickly between the domains to avoid detection.
- #### Use of Command-Line Interface
	On gaining access to the target system, an adversary can make use of the command-line interface to interact with the target system, browse the files, read file content, modify file content, create new accounts, connect to the remote system, and download and install malicious code.
- #### HTTP User Agent
	In HTTP-based communication, the server identifies the connected HTTP client using the user agent field.
- #### Command and Control Server
	Adversaries use command and control servers to communicate remotely with compromised systems through an encrypted session.
- #### Use of DNS Tunneling
	Adversaries use DNS tunneling to obfuscate malicious traffic in the legitimate traffic carried by common protocols used in the network.
- #### Use of Web Shell
	And adversary uses a web shell to manipulate the web server by creating a shell within a website; it allows an adversary to gain remote access to the functionalities of a server.
- #### Data Staging
	After successful penetration into a target's network, the adversary uses data staging techniques to collect and combine as much data as possible.
	
## Indicator of Compromise (IoCs)

Indicators  of compromise are the clues, artifacts, and pieces of forensic data that are found on a network or operating system of an organization that indicate a potential intrusion or malicious activity in the organization's infrastructure.
Cyber Threats are continuously evolving with the newer TTPs adapted based on the vulnerabilities of the target organization. Security professionals must perform continuous monitoring of IoCs to effectively and efficiently detect and respond to evolving cyber threats.

#### Categories of Indicators of Compromise
The cybersecurity professionals must have proper knowledge about various possible threat actors and their tactics related to cyber threats, mostly called (IoCs). For this purpose, IoCs are divided into four categories:

- #### Email Indicators
	Attackers usually prefer email services to send malicious data to the target organization or individual.
- #### Network Indicators
	Network indicators are useful for command and controls, malware delivery, and identifying details about the operating system, browser type, and other computer specific information.
- #### Host-Based indicators
	Host-Based indicators are found by performing an analysis of the infected system within the organizational network.
- #### Behavioral Indicators
	Generally, typical IoCs are useful for identifying indications of intrusion, such as malicious IP addresses, virus signatures, MD5 hash, and domain names.

## Hacking Concepts
Hacking in the field of computer security refers to exploiting system vulnerabilities and compromising security controls to gain unauthorized or inappropriate access to system resources.

### Who is a Hacker?
- An intelligent individual with `excellent computer skills` who can create and explore computer software and hardware.
- For some hackers, `hacking is a hobby` to see how many computers or networks they can compromise.
- Some hacker's intentions can either be to gain knowledge or to `probe and do illegal things`

### Hackers Classes
Hackers usually fall into one of the following categories, according to their activities:
- Black Hats: `Illegal or malicious purposes.`
- White Hats: `Defensive or for good purposes.`
- Gray Hats: `Work in two sides offensively and defensively.`
- Suicide Hackers: `They give a shit the consequences of their actions.`
- Script Kiddies: `People who use tools made by real hackers they are (fake hackers).`
- Cyber Terrorists: `Motivated by religious or political beliefs.`
- State-Sponsored `Hackers: Contractors by governments for hack other governments.`
- Hacktivist: `Hacktivist is when hackers break into government or corporate computer systems as an act of protest.`

### Hacking Phases
In general, there are five phases of hacking:
-	#### Reconnaissance:
	Reconnaissance refers to the preparatory phase in which an attacker gathers as much information as possible about the target prior to launching the attack.
	- Reconnaissance Types:
		- Active: `Involve direct interactions with the target system by using tools to detect open ports, host, router locations, VoIP calls, among others`.
		- Passive: `They do not interact with the target directly. Relies on publicly available information (OSINT)`.
-	#### Scanning:
     Scanning is the phase immediately preceding the attack. The attacker uses the details gathered during reconnaissance to scan the network for specific information.
	- Pre-attack phase: `Scanning refers to the pre-attack phase when the attacker scans the network for specific information based on information gathered during reconnaissance.`
	 - Port Scanner: `Scanning can include the use of dialers, port scanners, network mappers, ping tools, and vulnerabilty scanners.`
	 - Extract Information: `Attackers extract information such as live machines, port, port status, OS details, device type and system uptime to launch attack.`
-	#### Gaining Access:
	- Gaining access refers to the point where the attacker obtains access to the operating system or applications on the target computer or network.
	- The attacker can gain access at the operating system, application, or network levels.
	- Can [[What is Privilege Escalation? | escalate privileges]] to obtain complete control of the system. In this process, the target's connected intermediate systems are also compromised.
	- Examples include `password cracking, buffer overflows, denial of service, and session hijacking`
-	#### Maintaining Access:
	- Maintaining access refers to the phase when the attacker tries to retain their ownership on the system.
	- Attackers may prevent the system from being owned by other attackers by securing their exclusive access with backdoors, rootkits, or trojans.
	- Attackers can upload, download, or manipulate data, applications, and configurations on the owned system.
	- Attackers use the compromised system to launch further attacks.
-	#### Clearing Tracks:
	- Clearing tracks refers to the activities carried out by an attacker to hide malicious acts.
	- The attacker's intentions include obtaining continuing access to the victim's system, remaining unnoticed and uncaught, and deleting evidence that might lead to their prosecution.
	- The attacker overwrites the server, system, and application logs to avoid suspicion.
	
	### Why Ethical Hacking is Necessary
	Ethical hacking is necessary as it allows for counter attacks against malicious hackers through anticipating the methods used to break into the system.
	- To prevent hackers from gaining access to the organization's information systems.
	- To uncover vulnerabilities in systems and explore their potential as a security risk.
	- To analyze and strengthen an organization's security posture, including policies, network protection infrastructure, and end-user practices.
	- To provide adequate preventive measures in order to avoid security breaches.
	- To help safeguard customer data.
	- To enhance security awareness at all levels in a business.

### Scope and Limitations of Ethical Hacking
##### Scope:
- Ethical hacking is a crucial component of risk assessment, auditing, counter fraud, and information systems security best practices.
- It is used to identify risk and highlight remedial actions. It also reduces ICT (Information and Communications Technology) cost by resolving vulnerabilities.
##### Limitations:
- Unless the businesses already know what they are looking for and why the are hiring an outside vendor to hack systems in the first place, chances are there would not be much to gain from the experience.
- An ethical hacker can only help the organization to better understand its security system; it is up to the organization to place the right safeguards on the network.

### Skills of an Ethical Hacker
It is essential for an ethical hacker to acquire the knowledge and skills to become an expert hacker and to use this knowledge in a lawful manner. The technical and non-technical skills to be a good ethical hacker are discussed below:
- #### Technical Skills:
   - In-depth knowledge of major operating environments, such as Windows, Unix, Linux, and Macintosh.
   - In-depth knowledge of networking concepts, technologies, and related hardware and software.
   - A computer expert adept at technical domains.
   - The knowledge of security areas and related issues.
   - High technical knowledge of how to launch sophisticated attacks.

- #### Non-Technical Skills
   - The ability to quickly learn and adapt new technologies.
   - A strong work ethic and good problem solving and communication skills.
   - Commitment to an organization's security policies.
   - An awareness of local standards and laws.

### Information Security Controls
Information security controls prevent the occurrence of unwanted events and reduce risk to the organization;s information assets. The Basic security concepts critical to information on the internet are  CIA `confidentiality, integrity and availability`. The concepts related to the persons accessing the information are `authentication, authorization, and non-repudiation.`

### Information Assurance (IA)
- IA refers to the assurance that the integrity, availability, confidentiality, and authenticity of information and information systems is protected during the usage, processing, storage, and transmission of information.
- Some of the processes that help in achieving information assurance include:
  - Developing local policy, process, and guidance.
  - Designing network and user authentication strategies.
  - Identifying network vulnerabilities and threats.
  - Identifying problem and resource requirements.
  - Creating plans for identified resource requirements.
  - Applying appropriate information assurance controls.
  - Performing certification and accreditation.
  - Providing information assurance training.

### Defense-in-Depth
- Defense-in-depth is a security strategy in which several protection layers are placed throughout an information system.
- It helps to prevent direct attacks against the system and its data because a break in one layer only leads the attacker to the next layer.

### What is Risk?
Risk refers to the degree of uncertainty or expectation of potential damage that an adverse event may cause to the system or its resources, under specified conditions.

  - #### Risk Level
     Risk level is an assessment of the resulted impact on the network.

  - #### Risk Matrix
The risk matrix scales the risk occurrence or likelihood probability, along with its consequences or impact.
  - #### Risk Management
Risk management is the process of reducing and maintaining risk at an acceptable level by means of a well-defined and actively employed security program.
- #### Risk Management Phases:
  - #### Risk Identification:
`Identifies the sources`, causes, consequences, and other details of the internal and external risks affecting the security of the organization.
  - #### Risk Assessment:
`Assesses the organization's risk` and provides an estimate of the likelihood and impact of the risk.
  - #### Risk Treatment:
`Selects and implements appropriate controls` for the identified risks.
  - #### Risk Tracking:
`Ensures appropriate controls are implemented` to handle known risks and calculates the chances of a new risk occurring.
  - #### Risk Review:
`Evaluates the performance` of the implemented risk management strategies.

### Cyber Threat Intelligence
According to the Oxford dictionary, a threat is defined as "the possibility of a malicious attempt to damage or disrupt a computer network or system." A threat is a potential occurrence of an undesired event that can eventually damage and interrupt the operational and functional activities of an organization. A threat can affect the integrity and availability factors of an organization. The impact of threats is very great and may affect the state of the physical IT assets in an organization. The existence of threats may be accidental, intentional, or due to the impact of some action.

#### Types of Threat Intelligence
Threat intelligence is contextual information that describes threats and guides organizations in making various business decisions. It is extracted from a huge collection of sources and information.

- #### Strategic:
High level information on changing risks.
Consumed by high level executives and management.
- #### Tactical:
Information on attacker's TTPs.
Consumed by IT service and SOC Managers, administrators.
- #### Operational:
Information on a specific incoming attack.
Consumed by security managers and network defenders.
- #### Technical
Information on specific indicators of compromise.
Consumed by SOC staff and IR teams.

### Thread Modeling
Threat modeling is a risk assessment approach for analyzing the security of an application by capturing, organizing, and analyzing all the information that affects the security of an application.

#### Threat Modeling Process
- #### Identify Security Objectives:
Helps to determine how much effort needs to be put toward subsequent steps
- #### Application Overview:
Identify the components, data flows, and trust boundaries
- #### Decompose the Application:
Helps to find more relevant and more detailed threats
- #### Identify Threats:
Identify threats relevant to the control scenario and context using the information
obtained in steps 2 and 3
- #### Identify Vulnerabilities:
Identify weaknesses related to the threats found using vulnerability categories

### Incident Management
Incident management is a set of defined processes to identify, analyze, prioritize, and resolve security incidents to restore the system to normal service operations as soon as possible, and prevent recurrence of the incident.

#### Incident management includes the following:
- Vulnerability analysis
- Artifact analysis
- Security awareness training
- Intrusion detection
- Public or technology monitoring

#### The incident management process is designed to:
- Improve service quality
- Resolve problems proactively
- Reduce the impact of incidents on an organization or its business
- Meet service availability requirements
- Increase staff efficiency and productivity
- Improve user and customer satisfaction
- Assist in handling future incidents

### Incident Handling and Response
Incident handling and response (IH&R) is the process of taking organized and careful steps when reacting to a security incident or cyber attack. It is a set of procedures, actions, and measures taken against and unexpected event occurrence. It involves logging, recording, and resolving incidents that take place in the organization. It notes the incident, when it occurred, its impact, and its cause.

#### Steps involved in the IH&R process:
- #### Preparation:
The preparation phase includes performing an audit of resources and assets to determine the purpose of security and define the rules, policies and procedures that drive the IH&R process. 
- #### Incident recording and assignment:
In this phase, the initial reporting and recording of the incident take place.
- #### Incident Triage:
In this phase, the identified security incident are analyzed, validated, categorized, and prioritized.
- #### Notification:
in the notification phase, the IH&R team informs various stakeholders, including management, third-party vendors, and clients, about the identified incident.
- #### Containment:
This phase helps to prevent the spread of infection to other organizational assets, preventing additional damage.
- #### Evidence gathering and forensic analysis:
In this phase, the IH&R team accumulates all possible evidence related to the incident and submits it to the forensic department for investigation.
- #### Eradication:
In the eradication phase, the IH&R team removes or eliminates the root cause of the incident and closes all the attack vectors to prevent similar incident in the future.
- #### Recovery:
After eliminating the causes for the incidents, the IH&R team restores the affected systems, services, resources, and data through recovery.
- #### Post-incident Activities:
- Once the process is complete, the security incident requires additional review and analysis before closing the matter.
   - Incident documentation
   - Incident impact assessment
   - Reviewing and revising policies
   - Closing the investigation
   - Incident disclosure

### Role of AI and ML in Cyber Security
Machine learning (ML) and Artificial intelligence (AI) are now popularly used across various industries and applications due to the increase in computing power, data collection, and storage capabilities.

#### What are AI and ML?
`Artificial Intelligence ` A huge amount of collected data is fed into the AI, which processes and analyzes it to understand its details and trends.
`Machine Learning` is a branch of artificial intelligence (AI) that gives the systems the ability to self-learn without any explicit programs.
There are two types of ML classification techniques:
- #### Supervised learning:
Supervised learning uses algorithms that input a set of labeled training data to attempt to learn the differences between the given labels.
- #### Unsupervised learning:
Unsupervised learning makes use of algorithms that input unlabeled training data to attempt to reduce all the categories without guidance.

### Information Security Laws and Standards
Laws are a system of rules and guidelines that are enforced by a particular country or
community to govern behavior. A Standard is a "document established by consensus and approved by a recognized body that provides, for common and repeated use, rules, guidelines, or characteristics for activities or their results, aimed at the achievement of the optimum degree of order in a given context".

### Payment Card Industry Data Security Standard (PCI DSS)
Source: https://www.pcisecuritystandards.org
The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard for organizations that handle cardholder information for the major debit, credit, prepaid, e-purse, ATM, and POS cards. This standard offers robust and comprehensive standards and supporting materials to enhance payment card data security. These materials include a framework of specifications, tools, measurements, and support resources to help organizations ensure the safe handling of cardholder information.

#### PCI Data Security Standard - High Level Overview
 - #### Build and Maintain a Secure Network:
   - Install and maintain a firewall configuration to protect cardholder data.
   - Do not use vendor-supplied defaults for system passwords and other security parameters
- #### Protect Cardholder Data:
   - Protect stored cardholder data
   - Encrypt transmission of cardholder data across open, public networks
- #### Maintain a Vulnerability - Management Program:
   - Use and regularly update anti-virus software or programs
   - Develop and maintain secure systems and applications
- #### Implement Strong Access - Control Measures: 
   - Restrict access to cardholder data by business need to know
   - Assign a unique ID to each person with computer access
   - Restrict physical access to cardholder data
- #### Regularly Monitor and Test -Networks:
   - Track and monitor all access to network resources and cardholder data
   - Regularly test security systems and processes
- #### Maintain an Information - Security Policy:
   - Maintain a policy that addresses information security for all personnel

### ISO/IEC 27001:2013
ISO/IEC 27001:2013 specifies the requirements for establishing, implementing, maintaining, and continually improving an information security management system within the context of an organization. It includes requirements for the assessment and treatment of information security risks tailored to the needs of the organization.

The regulation is intended to be suitable for several different uses, including:

- Use within organizations to formulate security requirements and objectives
- Use within organizations as a way to ensure that security risks are cost-effectively
managed
- Use within organizations to ensure compliance with laws and regulations
- Defining new information security management processes 
- Identifying and clarifying existing information security management processes
- Use by the management of organizations to determine the status of information
security management activities
- Implementing business-enabling information security
- Use by organizations to provide relevant information about information security to
customers

#### Health Insurance Portability and Accountability Act (HIPAA)
The HIPAA Privacy Rule provides federal protections for the individually identifiable health information held by covered entities and their business associates and gives patients an array of rights to that information. At the same time, the Privacy Rule permits the disclosure of health information needed for patient care and other necessary purposes.

The office of civil rights implemented HIPAA's Administrative Simplification Statute and Rules,
as discussed below:
- #### Electronic Transactions and Code Set Standards:
Transactions are electronic exchanges involving the transfer of information between
two parties for specific purposes. The Health Insurance Portability and Accountability
Act of 1996 (HIPAA) designated certain types of organizations as covered entities, including health plans, health care clearinghouses, and certain health care providers. 
- #### Privacy Rule
The HIPAA Privacy Rule establishes national standards to protect people's medical
records and other personal health information and applies to health plans, health care
clearinghouses, and health care providers that conduct certain health care transactions electronically. 
- #### Security Rule
The HIPAA Security Rule establishes national standards to protect individuals' electronic personal health information that is created, received, used, or maintained by a covered entity. 
- #### Employer Identifier Standard
The HIPAA requires that each employer has a standard national number that identifies
them on standard transactions.
- #### National Provider Identifier Standard (NPI)
The National Provider Identifier (NPI) is a HIPAA Administrative Simplification Standard. The NPI is a unique identification number assigned to covered health care providers.
- #### Enforcement Rule
The HIPAA Enforcement Rule contains provisions relating to compliance and investigation, as well as the imposition of civil monetary penalties for violations of the HIPAA Administrative Simplification Rules and procedures for hearings.

### Sarbanes Oxley Act (SOX)
Source: https://www.sec.gov
Enacted in 2002, the Sarbanes-Oxley Act aims to protect the public and investors by increasing the accuracy and reliability of corporate disclosures. This act does not explain how an organization must store records but describes the records that organizations must store and the duration of their storage. The Act mandated several reforms to enhance corporate responsibility, enhance financial disclosures, and combat corporate and accounting fraud.

### The Digital Millennium Copyright Act (DMCA)
Source: https://www.copyright.gov
The DMCA is an American copyright law that implements two 1996 treaties from the World Intellectual Property Organization (WIPO): the WIPO Copyright Treaty and the WIPO Performances and Phonograms Treaty. In order to implement US treaty obligations, the DMCA defines legal prohibitions against circumvention of the technological protection measures employed by copyright owners to protect their works, and against the removal or alteration of copyright management information. 

### Cyber Law in Different Countries
Cyberlaw or Internet law refers to any laws that deal with protecting the Internet and other online communication technologies. Cyberlaw covers topics such as Internet access and usage, privacy, freedom of expression, and jurisdiction. Cyber laws provide an assurance of the integrity, security, privacy, and confidentiality of information in both governmental and private organizations. These laws have become prominent due to the increase in Internet usage around the world. Cyber laws vary by jurisdiction and country, so implementing them is quite challenging. Violating these laws results in punishments ranging from fines to imprisonment.

