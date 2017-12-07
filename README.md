### This fork shows attacks from T-Pot

The honeypot software can be found here:
https://dtag-dev-sec.github.io/mediator/feature/2016/10/31/t-pot-16.10.html

The javascript was made by MatthewClarkMay
https://github.com/MatthewClarkMay/geoip-attack-map



### First and Foremost
thanks to MatthewClarkMay for the first version. Please let me know if you find any bugs.

### Cyber Security GeoIP Attack Map Visualization
This geoip attack map visualizer was developed to display network attacks on your organization in real time. The data server connects to elasticsearch, and parses out source IP, destination IP, source port, and destination port. Protocols are determined via common ports, and the visualizations vary in color based on protocol type. [CLICK HERE](https://www.youtube.com/watch?v=zTvLJjTzJnU) for a demo video. This project would not be possible if it weren't for Sam Cappella, who created a cyber defense competition network traffic visualizer for the 2015 Palmetto Cyber Defense Competition. I mainly used his code as a reference, but I did borrow a few functions while creating the display server, and visual aspects of the webapp. I would also like to give special thanks to [Dylan Madisetti](http://www.dylanmadisetti.com/) as well for giving me advice about certain aspects of my implementation.

### Important
This program relies entirely on elasticsearch for geolookup, and because all appliances format logs differently, you will need to customize the log parsing function(s).

### Configs 
1. Make sure in **/etc/redis/redis.conf** to change **bind 127.0.0.1** to **bind 0.0.0.0** if you plan on running the DataServer on a different machine than the AttackMapServer.
2. Make sure that the WebSocket address in **/AttackMapServer/index.html** points back to the IP address of the **AttackMapServer** so the browser knows the address of the WebSocket.
3. Add headquarters latitude/longitude to hqLatLng variable in **index.html**

### Bugs, Feedback, and Questions
If you find any errors or bugs, please let me know. Questions and feedback are also welcome, and can be sent to mcmay.web@gmail.com, or open an issue in this repository.


### Deploy example
Tested on Ubuntu 16.04 LTS.

* Clone the application:

  ```sh
  git clone https://github.com/matthewclarkmay/geoip-attack-map.git
  ```

* Install system dependencies:

  ```sh
  sudo apt install python3-pip redis-server

  ```

* Install python requirements:

  ```sh
  cd geoip-attack-map
  sudo pip3 install -U -r requirements.txt

  ```
  
* Start Redis Server:

  ```sh
  redis-server

  ```
* Start the Data Server:

  ```sh
  python DataServer_v2.py

  ```
* Start the Attack Map Server:
  
  ```sh
  python AttackMapServer.py
  ```
 
* Access the Attack Map Server from browser:

    * [http://localhost:8888/](http://localhost:8888/) or [http://127.0.0.1:8888/](http://127.0.0.1:8888/)
  
    * To access via browser on another computer, use the external IP of the machine running the AttackMapServer.
    
     * Edit the IP Address in the file "/static/map.js" at "AttackMapServer" directory. From:
      
       ```javascript
       var webSock = new WebSocket("ws:/127.0.0.1:8888/websocket");
       ```
     * To, for example: 
     
       ```javascript
       var webSock = new WebSocket("ws:/192.168.1.100:8888/websocket");
       ```
     * Restart the Attack Map Server:
     
       ```sh
       sudo python3 AttackMapServer.py
       ```
     * On the other computer, points the browser to:
     
       ```sh
       http://192.168.1.100:8888/
       ```
