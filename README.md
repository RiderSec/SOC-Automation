# Project Overview

In this project, I installed Wazuh on a VM to manage data sent by a Windows 10 Wazuh Host which I installed sysmon on. I generated telemetry using mimikatz and created a rule to gain some visibility on mimikatz usage regardless of if the filename was changed. I also used Shuffle to automate an email, to be sent to a SOC analyst, to notify them when mimikatz is started on a victim machine, for example.

# Setup

I made my setup on virtual machines, but we can also use the cloud should we need or want to.

The network is as follows:

<img width="594" height="461" alt="Diagrama sin título drawio" src="https://github.com/user-attachments/assets/6207d723-dbf0-4073-bd2f-9ff3456edd55" />

Luckily, Wazuh makes it very easy for us to install the manager or the agent on any of our machines. For the wazuh manager machine we can look at their docs and run the commands associated to them, and once we have it installed we can go into agents -> then create new agent, we tell wazuh the agent's name, the OS and the group it belongs to. At the end we have a command we can copy and paste on the machine we want to be an agent.

On our windows machine, we should install sysmon using Olafhartong's sysmon config: https://github.com/olafhartong/sysmon-modular, so we can gather logs.

On this test I downloaded mimikatz to generate telemetry, but we can really search for any behaviour we'd like to find on the agent machine.

For mimikatz or any malware really we'll have to create an exception for Windows Defender, so our test malware isn't blocked. We do this by going into Windows Security and setting a folder as an exception on Windows Security.

# Detection

So now that the setup is complete, we have to actually detect the use of mimikatz, for this we can use a custom rule such as this one:

```
<rule id="100002" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz usage detected (T1003 Credential Dumping)</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
```

This looks for sysmon event ID 1 (Process Creation) by matching the original filename of the file to "mimikatz.exe", and sets the mitre ATT&CK tactic to T1003 (Credential Dumping).

Once we save this rule and open mimikatz on our victim machine, we should (if we've done everything right, that is) get an alert such as this one:

<img width="2541" height="50" alt="imagen" src="https://github.com/user-attachments/assets/e8400c21-a416-4338-87e1-bd9b7dfb7076" />

# Automating alert emails using Shuffle

To be able to alert a SOC analyst that mimikatz is being used on our agent machine via email, we need to use a SOAR platform, in this example we'll be using Shuffle.

We should make an account on shuffle, and then we'll be greeted with a "change me" icon.

We remove it, add a webhook, copy the webhook link and paste it into our `ossec.conf` file with these parameters: 

```
<integration>
  <name>shuffle</name>
  <hook_url>[YOUR_SHUFFLE_WEBHOOK_URL]</hook_url>
  <rule_id>100002</rule_id>
  <alert_format>json</alert_format>
</integration>
```

So here we've just integrated shuffle with wazuh, by having Wazuh send the details of the alert once the rule id (in this case, rule 100002) is matched.

Now on shuffle, we can parse out the SHA256 associated with the file using regex, by creating a regex capture group, selecting the input data as the hashes from the matched rule ID and parsing out the SHA256 data like so:

<img width="1217" height="685" alt="imagen" src="https://github.com/user-attachments/assets/6bd1ff6a-fb41-4e14-9477-846816c627e1" />

This makes it so we can send it to VirusTotal using their API and get some more info on the hash, like if it may be malicious.

For this we just look for VirusTotal's app on Shuffle, drag and drop it over, authenticate using our API key and click on the option to get a hash report. 

Once here, we click to add the hash we've parsed out earlier as the ID parameter for our virustotal API call and test if it works.

If everything went well it should look like this:

<img width="287" height="531" alt="imagen" src="https://github.com/user-attachments/assets/f8170d82-fc49-46f8-ae9b-21becae44547" />

Now, to send an email to an address of our choosing with information about the incident we drag and drop the email implementation, then paste in the email address we wish to send the email to along with the subject and body of the email, in this case, we simply alerted the user that mimikatz was being used, but with the implementation we made, we could let the user know how many vendors consider it malicious and other info about the hash provided.

If everything worked correctly we should get something like this in the email inbox of the email address we specified earlier:

<img width="464" height="100" alt="imagen" src="https://github.com/user-attachments/assets/d2902188-6a16-4eb7-a1dc-78af7c80f2f8" />

# Conclusion

This was a challenging but fun project, that taught me a lot about how SOAR platforms work and about how to automate certain alerts in my workflow.


