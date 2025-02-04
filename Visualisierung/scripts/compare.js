const kyberURL = "data/kyber.csv";
const sphincsURL = "data/sphincs.csv";
const diffieHellmanURL = "data/diffie-hellman.csv";

function finalCompare() {
        loadCompare("compareViz1", 2, 1, [sphincsURL, diffieHellmanURL]);
        loadCompare("compareViz2", 1, 2, [kyberURL, diffieHellmanURL]);
        load3Compare("compareViz3", 2, 3, 1, [kyberURL, diffieHellmanURL, sphincsURL]);
        loadCompare("compareViz4", 4, 6, [kyberURL, diffieHellmanURL]);
}

async function loadCompare(plot, headerNo1, headerNo2, csvUrls) {
  try {
    // Wir gehen hier davon aus, dass es genau 2 CSV-Dateien sind.
    if (csvUrls.length < 2) {
      console.error("Es werden mindestens zwei CSV-Dateien benötigt.");
      return;
    }

    // Lade beide CSV-Dateien parallel
    const [data1, data2] = await Promise.all([
      d3.csv(csvUrls[0]),
      d3.csv(csvUrls[1])
    ]);

    // Für die Achsenbeschriftungen Spaltentitel nehmen
    const xAxisLabel = data1.columns[0] || "X";
    const yAxisLabel1 = data1.columns[headerNo1] || "Y1";
    const yAxisLabel2 = data2.columns[headerNo2] || "Y2";

    // x- und y-Werte jeweils in "xVal" und "yVal" konvertieren
    // 1) Erstes CSV => x aus Spalte 0, y aus headerNo1
    data1.forEach(d => {
      d.xVal = +d[data1.columns[0]];
      d.yVal = +d[data1.columns[headerNo1]];
    });

    // 2) Zweites CSV => x aus Spalte 0, y aus headerNo2
    data2.forEach(d => {
      d.xVal = +d[data2.columns[0]];
      d.yVal = +d[data2.columns[headerNo2]];
    });

    // Alle Daten sammeln, damit die Skalen (Domain) korrekt sind
    const allData = [...data1, ...data2];

    // Vorhandenes SVG entfernen
    d3.select("#" + plot).selectAll("svg").remove();

    // Neues SVG erstellen
    const margin = { top: 35, right: 20, bottom: 40, left: 70 };
    const width = 780 - margin.left - margin.right;
    const height = 395 - margin.top - margin.bottom;

    const svg = d3
      .select("#" + plot)
      .append("svg")
      .attr("width", width + margin.left + margin.right)
      .attr("height", height + margin.top + margin.bottom)
      .style("display", "block")
      .style("margin", "0 auto")
      .append("g")
      .attr("transform", `translate(${margin.left},${margin.top})`);

    // Skalen definieren
    const x = d3
      .scaleLinear()
      .domain(d3.extent(allData, d => d.xVal))
      .range([0, width]);

    const y = d3
      .scaleLinear()
      .domain(d3.extent(allData, d => d.yVal)).nice()
      .range([height, 0]);

    // X-Achse
    svg
      .append("g")
      .attr("transform", `translate(0,${height})`)
      .call(d3.axisBottom(x));

    svg
      .append("text")
      .attr("text-anchor", "middle")
      .attr("x", width / 2)
      .attr("y", height + 30)
      .text(xAxisLabel);

    // Y-Achse
    svg.append("g").call(d3.axisLeft(y));

    // Sammeltext für die Y-Achsenbeschriftung
    svg
      .append("text")
      .attr("text-anchor", "middle")
      .attr("transform", "rotate(-90)")
      .attr("x", -height / 2)
      .attr("y", -margin.left + 20)
      .text("microseconds"); //

    // Farben für die unterschiedlichen CSVs
    const colors = ["steelblue", "orange"];

    // 1) Erstes Dataset plotten
    const line1 = d3
      .line()
      .x(d => x(d.xVal))
      .y(d => y(d.yVal));

    svg
      .append("path")
      .datum(data1)
      .attr("fill", "none")
      .attr("stroke", colors[0])
      .attr("stroke-width", 1.5)
      .attr("d", line1);

    // 2) Zweites Dataset plotten
    const line2 = d3
      .line()
      .x(d => x(d.xVal))
      .y(d => y(d.yVal));

    svg
      .append("path")
      .datum(data2)
      .attr("fill", "none")
      .attr("stroke", colors[1])
      .attr("stroke-width", 1.5)
      .attr("d", line2);

    // Legende anzeigen
    const legendData = [
      { name: yAxisLabel1, color: colors[0] },
      { name: yAxisLabel2, color: colors[1] }
    ];

    const legend = svg
      .selectAll(".legend")
      .data(legendData)
      .enter()
      .append("g")
      .attr("class", "legend")
      .attr("transform", (_, i) => `translate(0, ${i * 20})`);

    legend
      .append("rect")
      .attr("x", width - 120)
      .attr("width", 12)
      .attr("height", 12)
      .style("fill", d => d.color);

    legend
      .append("text")
      .attr("x", width - 100)
      .attr("y", 10)
      .text(d => d.name);

  } catch (error) {
    console.error("Fehler beim Laden der CSV-Daten:", error);
  }
}

async function load3Compare(plot, headerNo1, headerNo2, headerNo3, csvUrls) {
  try {
    // Prüfe, ob mindestens 3 URLs vorhanden sind
    if (csvUrls.length < 3) {
      console.error("Es werden mindestens drei CSV-Dateien benötigt.");
      return;
    }

    // Lade die drei CSV-Dateien parallel
    const [data1, data2, data3] = await Promise.all([
      d3.csv(csvUrls[0]),
      d3.csv(csvUrls[1]),
      d3.csv(csvUrls[2])
    ]);

    // Für die Achsenbeschriftungen Spaltennamen nutzen
    const xAxisLabel = data1.columns[0] || "X-Werte";
    const yAxisLabel1 = data1.columns[headerNo1] || "Y1";
    const yAxisLabel2 = data2.columns[headerNo2] || "Y2";
    const yAxisLabel3 = data3.columns[headerNo3] || "Y3";

    // Daten konvertieren (xVal, yVal) anhand der Spaltenindizes:
    // 1) Erstes CSV => x aus Spalte 0, y aus headerNo1
    data1.forEach(d => {
      d.xVal = +d[data1.columns[0]];
      d.yVal = +d[data1.columns[headerNo1]];
    });

    // 2) Zweites CSV => x aus Spalte 0, y aus headerNo2
    data2.forEach(d => {
      d.xVal = +d[data2.columns[0]];
      d.yVal = +d[data2.columns[headerNo2]];
    });

    // 3) Drittes CSV => x aus Spalte 0, y aus headerNo3
    data3.forEach(d => {
      d.xVal = +d[data3.columns[0]];
      d.yVal = +d[data3.columns[headerNo3]];
    });

    // Alle Daten sammeln, damit die Skalen (Domain) korrekt über alle CSVs hinweg berechnet werden
    const allData = [...data1, ...data2, ...data3];

    // Vorhandenes SVG entfernen
    d3.select("#" + plot).selectAll("svg").remove();

    // Neues SVG erstellen
    const margin = { top: 35, right: 20, bottom: 40, left: 70 };
    const width = 780 - margin.left - margin.right;
    const height = 395 - margin.top - margin.bottom;

    const svg = d3
      .select("#" + plot)
      .append("svg")
      .attr("width", width + margin.left + margin.right)
      .attr("height", height + margin.top + margin.bottom)
      .style("display", "block")
      .style("margin", "0 auto")
      .append("g")
      .attr("transform", `translate(${margin.left},${margin.top})`);

    // Skalen definieren
    const x = d3
      .scaleLinear()
      .domain(d3.extent(allData, d => d.xVal))
      .range([0, width]);

    const y = d3
      .scaleLinear()
      .domain(d3.extent(allData, d => d.yVal)).nice()
      .range([height, 0]);

    // X-Achse
    svg
      .append("g")
      .attr("transform", `translate(0,${height})`)
      .call(d3.axisBottom(x));

    svg
      .append("text")
      .attr("text-anchor", "middle")
      .attr("x", width / 2)
      .attr("y", height + 30)
      .text(xAxisLabel);

    // Y-Achse
    svg.append("g").call(d3.axisLeft(y));

    // Y-Achsen Beschriftung 
    svg
      .append("text")
      .attr("text-anchor", "middle")
      .attr("transform", "rotate(-90)")
      .attr("x", -height / 2)
      .attr("y", -margin.left + 20)
      .text("microseconds");

    // Farben für die unterschiedlichen CSVs
    const colors = ["steelblue", "orange", "green"];

    // Linie für erstes Dataset
    const line1 = d3.line()
      .x(d => x(d.xVal))
      .y(d => y(d.yVal));

    svg
      .append("path")
      .datum(data1)
      .attr("fill", "none")
      .attr("stroke", colors[0])
      .attr("stroke-width", 1.5)
      .attr("d", line1);

    // Linie für zweites Dataset
    const line2 = d3.line()
      .x(d => x(d.xVal))
      .y(d => y(d.yVal));

    svg
      .append("path")
      .datum(data2)
      .attr("fill", "none")
      .attr("stroke", colors[1])
      .attr("stroke-width", 1.5)
      .attr("d", line2);

    // Linie für drittes Dataset
    const line3 = d3.line()
      .x(d => x(d.xVal))
      .y(d => y(d.yVal));

    svg
      .append("path")
      .datum(data3)
      .attr("fill", "none")
      .attr("stroke", colors[2])
      .attr("stroke-width", 1.5)
      .attr("d", line3);

    //  Legende 
    const legendData = [
      { name: yAxisLabel1, color: colors[0] },
      { name: yAxisLabel2, color: colors[1] },
      { name: yAxisLabel3, color: colors[2] }
    ];

    const legend = svg
      .selectAll(".legend")
      .data(legendData)
      .enter()
      .append("g")
      .attr("class", "legend")
      .attr("transform", (_, i) => `translate(0, ${i * 20})`);

    legend
      .append("rect")
      .attr("x", width - 120)
      .attr("width", 12)
      .attr("height", 12)
      .style("fill", d => d.color);

    legend
      .append("text")
      .attr("x", width - 100)
      .attr("y", 10)
      .text(d => d.name);

  } catch (error) {
    console.error("Fehler beim Laden der CSV-Daten:", error);
  }
}

// Initialisierung bei Seitenlade
document.addEventListener("DOMContentLoaded", finalCompare);
