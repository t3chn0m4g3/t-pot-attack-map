// To access by a browser in another computer, use the external IP of machine running AttackMapServer
// from the same computer(only), you can use the internal IP.
// Example:
// - AttackMapServer machine:
//   - Internal IP: 127.0.0.1
//   - External IP: 192.168.11.106
// For Proxy_Pass to work we need to use wss:// instead of ws://
const WS_HOST = 'ws://'+window.location.host+'/websocket'
var webSock = new WebSocket(WS_HOST); // Internal

// Link map
L.mapbox.accessToken = 'pk.eyJ1IjoiZWRkaWU0IiwiYSI6ImNqNm5sa2lvbTBjYWQyeG50Mnc0dnBzN2gifQ.tYmx_1LwtL3yHsLbC6CT3g';

var map = L.map('map', {
    "scrollWheelZoom": false,
    "doubleClickZoom": false,
    "zoomControl": false
});
map.setView([0, -4.932], 3)
map.addLayer(L.mapbox.styleLayer('mapbox://styles/mapbox/dark-v10'));

// Add full screen option
L.control.fullscreen().addTo(map);

// Append <svg> to map
var svg = d3.select(map.getPanes().overlayPane).append("svg")
            .attr("class", "leaflet-zoom-animated")
            .attr("width", window.innerWidth)
            .attr("height", window.innerHeight);

function translateSVG() {
    var viewBoxLeft = document.querySelector("svg.leaflet-zoom-animated").viewBox.animVal.x;
    var viewBoxTop = document.querySelector("svg.leaflet-zoom-animated").viewBox.animVal.y;

    // Resizing width and height in case of window resize
    svg.attr("width", window.innerWidth);
    svg.attr("height", window.innerHeight);

    // Adding the ViewBox attribute to our SVG to contain it
    svg.attr("viewBox", function () {
        return "" + viewBoxLeft + " " + viewBoxTop + " "  + window.innerWidth + " " + window.innerHeight;
    });

    // Adding the style attribute to our SVG to translate it
    svg.attr("style", function () {
        return "transform: translate3d(" + viewBoxLeft + "px, " + viewBoxTop + "px, 0px);";
    });
}

function update() {
    translateSVG();
    // additional stuff
}

// Re-draw on reset, this keeps the markers where they should be on reset/zoom
map.on("moveend", update);

function calcMidpoint(x1, y1, x2, y2, bend) {
    if(y2<y1 && x2<x1) {
        var tmpy = y2;
        var tmpx = x2;
        x2 = x1;
        y2 = y1;
        x1 = tmpx;
        y1 = tmpy;
    }
    else if(y2<y1) {
        y1 = y2 + (y2=y1, 0);
    }
    else if(x2<x1) {
        x1 = x2 + (x2=x1, 0);
    }

    var radian = Math.atan(-((y2-y1)/(x2-x1)));
    var r = Math.sqrt(x2-x1) + Math.sqrt(y2-y1);
    var m1 = (x1 + x3)/2;
    var m2 = (y1 + y2)/2;

    var min = 2.5, max = 7.5;
    //var min = 1, max = 7;
    var arcIntensity = parseFloat((Math.random() * (max - min) + min).toFixed(2));

    if (bend === true) {
        var a = Math.floor(m1 - r * arcIntensity * Math.sin(radian));
        var b = Math.floor(m2 - r * arcIntensity * Math.cos(radian));
    } else {
        var a = Math.floor(m1 + r * arcIntensity * Math.sin(radian));
        var b = Math.floor(m2 + r * arcIntensity * Math.cos(radian));
    }

    return {"x":a, "y":b};
}

function translateAlong(path) {
    var l = path.getTotalLength();
    return function(i) {
        return function(t) {
            // Put in try/catch because sometimes floating point is stupid..
            try {
            var p = path.getPointAtLength(t*l);
            return "translate(" + p.x + "," + p.y + ")";
            } catch(err){
            console.log("Caught exception.");
            return "ERROR";
            }
        }
    }
}

function handleParticle(msg, srcPoint) {
    var i = 0;
    var x = srcPoint['x'];
    var y = srcPoint['y'];

    svg.append('circle')
        .attr('cx', x)
        .attr('cy', y)
        .attr('r', 1e-6)
        .style('fill', 'none')
        .style('stroke', msg.color)
        .style('stroke-opacity', 1)
        .transition()
        .duration(2000)
        .ease(Math.sqrt)
        .attr('r', 35)
        .style('stroke-opacity', 1e-6)
        .remove();
}

function handleTraffic(msg, srcPoint, hqPoint) {
    var fromX = srcPoint['x'];
    var fromY = srcPoint['y'];
    var toX = hqPoint['x'];
    var toY = hqPoint['y'];
    var bendArray = [true, false];
    var bend = bendArray[Math.floor(Math.random() * bendArray.length)];

    var lineData = [srcPoint, calcMidpoint(fromX, fromY, toX, toY, bend), hqPoint]
    var lineFunction = d3.svg.line()
        .interpolate("basis")
        .x(function(d) {return d.x;})
        .y(function(d) {return d.y;});

    var lineGraph = svg.append('path')
            .attr('d', lineFunction(lineData))
            .attr('opacity', 0.8)
            .attr('stroke', msg.color)
            .attr('stroke-width', 2)
            .attr('fill', 'none');

    if (translateAlong(lineGraph.node()) === 'ERROR') {
        console.log('translateAlong ERROR')
        return;
    }

    var circleRadius = 6

    // Circle follows the line
    var dot = svg.append('circle')
        .attr('r', circleRadius)
        .attr('fill', msg.color)
        .transition()
        .duration(700)
        .ease('ease-in')
        .attrTween('transform', translateAlong(lineGraph.node()))
        .each('end', function() {
            d3.select(this)
                .transition()
                .duration(500)
                .attr('r', circleRadius * 2.5)
                .style('opacity', 0)
                .remove();
    });

    var length = lineGraph.node().getTotalLength();
    lineGraph.attr('stroke-dasharray', length + ' ' + length)
        .attr('stroke-dashoffset', length)
        .transition()
        .duration(700)
        .ease('ease-in')
        .attr('stroke-dashoffset', 0)
        .each('end', function() {
            d3.select(this)
                .transition()
                .duration(100)
                .style('opacity', 0)
                .remove();
    });
}

var circles = new L.LayerGroup();
map.addLayer(circles);

function addCircle(msg, srcLatLng) {
    circleCount = circles.getLayers().length;
    circleArray = circles.getLayers();

    // Only allow 50 circles to be on the map at a time
    if (circleCount >= 100) {
        circles.removeLayer(circleArray[0]);
    }

    L.circle(srcLatLng, 50000, {
        color: msg.color,
        fillColor: msg.color,
        fillOpacity: 0.2,
    }).addTo(circles);
}

function prependAttackRow(id, args) {
    var tr = document.createElement('tr');
    count = args.length;

    for (var i = 0; i < count; i++) {
        var td = document.createElement('td');
        if (args[i] === args[2]) {
            var path = 'flags/' + args[i] + '.png';
            var img = document.createElement('img');
            img.src = path;
            td.appendChild(img);
            tr.appendChild(td);
        } else {
            var textNode = document.createTextNode(args[i]);
            td.appendChild(textNode);
            tr.appendChild(td);
        }
    }

    var element = document.getElementById(id);
    var rowCount = element.rows.length;

    // Only allow 50 rows
    if (rowCount >= 50) {
        element.deleteRow(rowCount -1);
    }

    element.insertBefore(tr, element.firstChild);
}

function redrawCountIP(hashID, id, countList, codeDict) {
    $(hashID).empty();
    var element = document.getElementById(id);

    // Sort ips greatest to least
    // Create items array from dict
    var items = Object.keys(countList[0]).map(function(key) {
        return [key, countList[0][key]];
    });
    // Sort the array based on the second element
    items.sort(function(first, second) {
        return second[1] - first[1];
    });
    // Create new array with only the first 50 items
    var sortedItems = items.slice(0, 50);
    var itemsLength = sortedItems.length;

    for (var i = 0; i < itemsLength; i++) {
        tr = document.createElement('tr');
        td1 = document.createElement('td');
        td2 = document.createElement('td');
        td3 = document.createElement('td');
        var key = sortedItems[i][0];
        value = sortedItems[i][1];
        var keyNode = document.createTextNode(key);
        var valueNode = document.createTextNode(value);
        var path = 'flags/' + codeDict[key] + '.png';
        var img = document.createElement('img');
        img.src = path;
        td1.appendChild(valueNode);
        td2.appendChild(img);

        var alink = document.createElement('a');
        alink.setAttribute("href","#");
        alink.setAttribute("class","showInfo");
        alink.style.color = "white";
        alink.appendChild(keyNode);

        td3.appendChild(alink);
        tr.appendChild(td1);
        tr.appendChild(td2);
        tr.appendChild(td3);
        element.appendChild(tr);
    }
}

function redrawCountIP2(hashID, id, countList, codeDict) {
    $(hashID).empty();
    var element = document.getElementById(id);

    // Sort ips greatest to least
    // Create items array from dict
    var items = Object.keys(countList[0]).map(function(key) {
        return [key, countList[0][key]];
    });
    // Sort the array based on the second element
    items.sort(function(first, second) {
        return second[1] - first[1];
    });
    // Create new array with only the first 50 items
    var sortedItems = items.slice(0, 50);
    var itemsLength = sortedItems.length;

    for (var i = 0; i < itemsLength; i++) {
        tr = document.createElement('tr');
        td1 = document.createElement('td');
        td2 = document.createElement('td');
        td3 = document.createElement('td');
        var key = sortedItems[i][0];
        value = sortedItems[i][1];
        var keyNode = document.createTextNode(key);
        var valueNode = document.createTextNode(value);
        var path = 'flags/' + codeDict[key] + '.png';
        var img = document.createElement('img');
        img.src = path;
        td1.appendChild(valueNode);
        td2.appendChild(img);

        td3.appendChild(keyNode);
        tr.appendChild(td1);
        tr.appendChild(td2);
        tr.appendChild(td3);
        element.appendChild(tr);
    }
}

function handleLegend(msg) {
    var ipCountList = [msg.ips_tracked,
               msg.iso_code];
    var countryCountList = [msg.countries_tracked,
                msg.iso_code];
    var attackList = [msg.event_time,
              msg.src_ip,
              msg.iso_code,
              msg.country,
              msg.city,
              msg.protocol];
    redrawCountIP('#ip-tracking','ip-tracking', ipCountList, msg.ip_to_code);
    redrawCountIP2('#country-tracking', 'country-tracking', countryCountList, msg.country_to_code);
    prependAttackRow('attack-tracking', attackList);
}

function handleLegendType(msg) {
    var attackType = [msg.type2];
    var attackCve = [msg.event_time,
             msg.type3,
             msg.iso_code,
             msg.src_ip,
             msg.country,
             msg.city,
             msg.protocol];

}

// Adds the HQ point to the map and its corresponding popup
function addHqToMap(hqLatLng, msg) {
    var marker = L.marker([hqLatLng.lat, hqLatLng.lng], {
        icon: L.mapbox.marker.icon({'marker-color': '#9c89cc'}),
    })
    .bindPopup(msg)
    .addTo(map);

    var popup = L.popup()
        .setLatLng(hqLatLng)
        .setContent(msg);
}

function formatMessage(msg) {
    return '<b> ' + msg.city_name + ', ' + msg.dst_country_code + ' </b>';
}

// Websocket Stuff
webSock.onmessage = function (e) {
    console.log("Got a websocket message...");
    try {
        var msg = JSON.parse(e.data);
        console.log(msg);
        switch(msg.type) {
        case "Traffic":
            console.log("Traffic!");
            var srcLatLng = new L.LatLng(msg.src_lat, msg.src_long);
            var hqLatLng = new L.LatLng(msg.dst_lat, msg.dst_long);
            var srcPoint = map.latLngToLayerPoint(srcLatLng);
            var hqPoint = map.latLngToLayerPoint(hqLatLng)
            console.log('');

            addCircle(msg, srcLatLng);
            addHqToMap(hqLatLng, formatMessage(msg));

            handleParticle(msg, srcPoint);
            handleTraffic(msg, srcPoint, hqPoint, srcLatLng);
            handleLegend(msg);
            handleLegendType(msg);
            break;
        }
    } catch (err) {
        console.log(err)
    }
}