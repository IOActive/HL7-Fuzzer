## HL7 message Fuzzer

#### What is HL7:

```
https://en.wikipedia.org/wiki/Health_Level_Seven_International
```

#### Clone the repo: 

```
https://github.com/IOActive/HL7-Fuzzer
```

### Install the requirements

```bash
pip3 install -r requirements.txt
```

### Directory structure

```bash
│───hl7fuzz.py              (Python fuzzer)
│───requirements.txt		(Requirements file to install modules the fuzzer depends on)
├───DB						(location of the fuzzing sessions saved in sqlite db)
├───messages				(The location where you put your HL7 messages so it can parse it and generate the fuzzed data)
└───payloads				(Folder containing some of the fuzzing strings that the fuzzer uses)
```

### Fuzzer Payloads

```python
self.strats = [b"A" * randrange(1, self.cmdargs.max), urandom(randrange(1, self.cmdargs.max)), choice(self.elements),choice(self.sqli),choice(self.xss), choice(self.fmtstr),choice(self.badstrings)]
```

1. Testing for overflows via sending long strings in a segment.
2. Sending random bytes in a segment.
3. Sending random sized elements that exist in a HL7  message " &, \ , ^ , ~" .
4. Sending format string specifiers in a segment.
5. Sending XSS payloads incase it triggers in a web interface.
6. Sending SQLI injection payloads
7. Sending bad characters in different languages and emoji's and the likes.

### How an HL7 Message looks like

* #### You can get these messages from the vendor you are testing with.

  * for a more on HL7 start from -> https://en.wikipedia.org/wiki/Health_Level_7 
    * http://www.hl7.org/implement/standards/product_brief.cfm?product_id=185
  * This fuzzer supports Version 2 messaging

```reStructuredText
MSH|^~\&|MegaReg|XYZHospC|SuperOE|XYZImgCtr|20060529090131-0500||ADT^A01^ADT_A01|01052901|P|2.5
EVN||200605290901||||200605290900
PID|||56782445^^^UAReg^PI||KLEINSAMPLE^BARRY^Q^JR||19620910|M||2028-9^^HL70005^RA99113^^XYZ|260 GOODWIN CREST DRIVE^^BIRMINGHAM^AL^35209^^M~NICKELL’S PICKLES^10000 W 100TH AVE^BIRMINGHAM^AL^35200^^O|||||||0105I30001^^^99DEF^AN
PV1||I|W^389^1^UABH^^^^3||||12345^MORGAN^REX^J^^^MD^0010^UAMC^L||67890^GRAINGER^LUCY^X^^^MD^0010^UAMC^L|MED|||||A0||13579^POTTER^SHERMAN^T^^^MD^0010^UAMC^L|||||||||||||||||||||||||||200605290900
OBX|1|NM|^Body Height||1.80|m^Meter^ISO+|||||F
OBX|2|NM|^Body Weight||79|kg^Kilogram^ISO+|||||F
AL1|1||^ASPIRIN
DG1|1||786.50^CHEST PAIN, UNSPECIFIED^I9|||A
```

### Tool Usage

* #### Help

```bash
$ python3 hl7fuzz.py -h 
usage: hl7fuzz.py [-h] [-f FOLDER] [-d IP] [-p PORT] [-s SAMPLES] [-c CHANGE] [-m MAX] [-t TARGET] [-a ALLPARTS]
                  [-v NOISEY] [-x DELAY] [-b SERVER] [-bp SERVERPORT]

An extremely dumb HL7 message fuzzer.

optional arguments:
  -h, --help            show this help message and exit
  -f FOLDER, --folder FOLDER
                        Folder containing hl7 messages as seperate text files.
  -d IP, --ip IP        Destination Ip address.
  -p PORT, --port PORT  Destination port.
  -s SAMPLES, --samples SAMPLES
                        Number of samples to generate.
  -c CHANGE, --change CHANGE
                        Fields to always change.
  -m MAX, --max MAX     Max length of fuzz generated string.
  -t TARGET, --target TARGET
                        Will change from random fuzz payload insertion into messages to defined areas that you
                        selected from a message which are defined by a delimiter of your choice.
  -a ALLPARTS, --allparts ALLPARTS
                        This will allow you to parse the first segment of an HL7 message instead of skipping the first
                        segment.
  -v NOISEY, --noisey NOISEY
                        to show both sent and received messages set this to 1
  -x DELAY, --delay DELAY
                        delay interval between sending packets. Set this to 0 for DoS attack/stress testing.
  -b SERVER, --server SERVER
                        Setup a server to respond with malicious HL7 messages. Set this option to 1 : --server 1
  -bp SERVERPORT, --serverport SERVERPORT
                        Setup the server port used with --server option .
```

* #### The --target option

  * this option will allow you to select and fuzz specific fields of the message instead of random fields in the message.
  * If you want to fuzz all fields in a random manner, do not set this option.
  * By passing the target option a value of \<fuzz\> it will replace the chosen fields with fuzz data.
  * This message should be saved in the messages folder.
 
 ```bash
   $ python3 hl7fuzz.py -f messages -s 100 --target "<fuzz>" -d 192.168.1.3 -p 9550 -m 2000
 ```
  
```reStructuredText
  MSH|^~\&|MegaReg|XYZHospC|<fuzz>|XYZImgCtr|20060529090131-0500||ADT^A01^ADT_A01|01052901|P|2.5
  EVN||200605290901||||200605290900
  PID|||56782445^^^UAReg^PI||KLEINSAMPLE^BARRY^Q^JR||19620910|M||2028-9^^HL70005^RA99113^^XYZ|260 GOODWIN CREST DRIVE^^BIRMINGHAM^AL^35209^^M~NICKELL’S PICKLES^10000 <fuzz> AVE^BIRMINGHAM^AL^35200^^O|||||||0105I30001^^^99DEF^AN
  PV1||I|W^389^1^UABH^^^^3||||12345^MORGAN^REX^J^^^MD^0010^UAMC^L||67890^GRAINGER^LUCY^X^^^MD^0010^UAMC^L|MED|||||A0||13579^POTTER^SHERMAN^T^^^MD^0010^UAMC^L|||||||||||||||||||||||||||<fuzz>
  OBX|1|NM|^Body Height||1.80|m^Meter^ISO+|||||F
  OBX|2|NM|^Body Weight||79|<fuzz>|||||F
  AL1|1||^ASPIRIN
  DG1|1||786.50^CHEST PAIN, UNSPECIFIED^I9|||A
```
 


* #### The --change option

  * When sending messages you might come across a reply saying that its a duplicate request. To get around this issue you can specify the field that needs to always have its value changed and the fuzzer will automatically do that for you.

    ```bash
    $ python3 hl7fuzz.py -f messages -s 100 --change 1,2 -d 192.168.1.3 -p 9550 -m 2000
    ```
 
  * the message will always change the second line in the message

  * \<THIS WILL BE CHANGED\> can be seen in the second line below

```reStructuredText
MSH|^~\&|MegaReg|XYZHospC|SuperOE|XYZImgCtr|20060529090131-0500||ADT^A01^ADT_A01|01052901|P|2.5
EVN||<THIS WILL BE CHANGED>||||200605290900
PID|||56782445^^^UAReg^PI||KLEINSAMPLE^BARRY^Q^JR||19620910|M||2028-9^^HL70005^RA99113^^XYZ|260 GOODWIN CREST DRIVE^^BIRMINGHAM^AL^35209^^M~NICKELL’S PICKLES^10000 W 100TH AVE^BIRMINGHAM^AL^35200^^O|||||||0105I30001^^^99DEF^AN
PV1||I|W^389^1^UABH^^^^3||||12345^MORGAN^REX^J^^^MD^0010^UAMC^L||67890^GRAINGER^LUCY^X^^^MD^0010^UAMC^L|MED|||||A0||13579^POTTER^SHERMAN^T^^^MD^0010^UAMC^L|||||||||||||||||||||||||||200605290900
OBX|1|NM|^Body Height||1.80|m^Meter^ISO+|||||F
OBX|2|NM|^Body Weight||79|kg^Kilogram^ISO+|||||F
AL1|1||^ASPIRIN
DG1|1||786.50^CHEST PAIN, UNSPECIFIED^I9|||A
```

* #### The --allparts option

  * if this option is set to zero it will not change any part of the first line of a message

  * The line below will not be touched if --allparts is set to its default value of zero.

    ```reStructuredText
    MSH|^~\&|MegaReg|XYZHospC|SuperOE|XYZImgCtr|20060529090131-0500||ADT^A01^ADT_A01|01052901|P|2.5
    ```
  
  * To have the ability to change the first segment pass the option --allparts 1 
  
    ```bash
    $ python3 hl7fuzz.py -f messages -s 100 --allparts 1  -d 192.168.1.3 -p 9550
    ```

### The Fuzzing server
  * The server simply replies with random data taken from `self.strats` to client sending an HL7 message.
  * The server session sqlite file will be saved in the DB folder with `-server` in the filename.
  * to start the server:
 
 ```bash
  $python3 hl7fuzz.py --server 1 --serverport 9550 -m 2000
  ```
    
