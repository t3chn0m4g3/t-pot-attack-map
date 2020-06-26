### This fork shows attacks from T-Pot

The honeypot software can be found here:
https://dtag-dev-sec.github.io/mediator/feature/2016/10/31/t-pot-16.10.html

The javascript was made by MatthewClarkMay
https://github.com/MatthewClarkMay/geoip-attack-map



### First and Foremost
thanks to MatthewClarkMay for the first version. Please let me know if you find any bugs.

### Cyber Security GeoIP Attack Map Visualization
This geoip attack map visualizer was developed to display network attacks on your organization in real time. The data server connects to elasticsearch, and parses out source IP, destination IP, source port, and destination port. Protocols are determined via common ports, and the visualizations vary in color based on protocol type. [CLICK HERE](https://www.youtube.com/watch?v=zTvLJjTzJnU) for a demo video. This project would not be possible if it weren't for Sam Cappella, who created a cyber defense competition network traffic visualizer for the 2015 Palmetto Cyber Defense Competition. I mainly used his code as a reference, but I did borrow a few functions while creating the display server, and visual aspects of the webapp. I would also like to give special thanks to [Dylan Madisetti](http://www.dylanmadisetti.com/) as well for giving me advice about certain aspects of my implementation.

