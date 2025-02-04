// Funktion, um CSV-Daten zu laden und Diagramm zu erstellen mit D3
function loadTimeFinal() {
    if (document.getElementById("alogrithmSelect").value == "kyber") {
        loadAndVisualizeData1("clientViz1", 1, 10);
        loadAndVisualizeData1("serverViz1", 2, 10);
        loadAndVisualizeData1("clientViz2", 3, 0);
        loadAndVisualizeData1("serverViz2", 4, 0);
        loadAndVisualizeData1("keyGenViz", 0, 0);
        loadAndVisualizeData1("keyGenViz2", 0, 0);

    }else if (document.getElementById("alogrithmSelect").value == "sphincs") {
        loadAndVisualizeData1("clientViz1", 3, 50);
        loadAndVisualizeData1("serverViz1", 4, 0);
        loadAndVisualizeData1("clientViz2", 1, 0);
        loadAndVisualizeData1("serverViz2", 2, 100);
        loadAndVisualizeData1("keyGenViz", 0, 0);
        loadAndVisualizeData1("keyGenViz2", 0, 0);
        
    }else if (document.getElementById("alogrithmSelect").value == "diffie-hellman") {
        loadAndVisualizeData1("clientViz1", 3, 10);
        loadAndVisualizeData1("serverViz1", 6, 10);
        loadAndVisualizeData1("clientViz2", 2, 15);
        loadAndVisualizeData1("serverViz2", 5, 15);
        loadAndVisualizeData1("keyGenViz", 1, 0);
        loadAndVisualizeData1("keyGenViz2", 4, 0);
        
    }
}

async function loadAndVisualizeData1(plot, headerNo, startModifier) {
    const algorithm = document.getElementById("alogrithmSelect").value;

    // Erstelle die CSV-Datei-URL basierend auf der Auswahl
    const csvUrl = `data/${algorithm.toLowerCase()}.csv`;

    try {
        // Lade die CSV-Daten
        const data = await d3.csv(csvUrl);

        // Extrahiere Header für Achsenbeschriftung
        const headers = data.columns; // CSV-Header werden automatisch als Array bereitgestellt
        const xAxisLabel = headers[0]; 
        const yAxisLabel = headers[headerNo]; 
        

        // Konvertiere die Daten
        data.forEach(d => {
            d[xAxisLabel] = +d[xAxisLabel]; // Konvertiere X-Werte zu Zahlen
            d[yAxisLabel] = +d[yAxisLabel]; // Konvertiere Y-Werte zu Zahlen
        });

        // Durchschnitt berechnen
        const yAvg = d3.mean(data, d => d[yAxisLabel]);


        // Entferne bestehendes SVG
        d3.select("#"+plot).selectAll("svg").remove();
        

        // Erstelle ein neues SVG
        const margin = { top: 35, right: 20, bottom: 40, left: 70 };
        const width = 780 - margin.left - margin.right;
        const height = 395 - margin.top - margin.bottom;

        const svg = d3
            .select("#"+plot)
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
            .domain(d3.extent(data, d => d[xAxisLabel]))
            .range([0, width]);

        const yMin = d3.min(data, d => d[yAxisLabel]);
        const yMax = d3.max(data, d => d[yAxisLabel]);
        const yStart = yAvg - yAvg/startModifier > 0 ? yAvg - yAvg/startModifier : 0; // Starte die Achse leicht unter dem Durchschnitt

        const y = d3
            .scaleLinear()
            .domain([yStart, yMax]).nice()
            .range([height, 0]);

        // X-Achse hinzufügen
        svg
            .append("g")
            .attr("transform", `translate(0,${height})`)
            .call(d3.axisBottom(x));

        // X-Achsenbeschriftung hinzufügen
        svg
            .append("text")
            .attr("text-anchor", "middle")
            .attr("x", width / 2)
            .attr("y", height + 30)
            .text(xAxisLabel);

        // Y-Achse hinzufügen
        svg.append("g").call(d3.axisLeft(y));

        // Y-Achsenbeschriftung hinzufügen
        svg
            .append("text")
            .attr("text-anchor", "middle")
            .attr("transform", `rotate(-90)`)
            .attr("x", -height / 2)
            .attr("y", -margin.left + 20)
            .text(yAxisLabel);

        // Linienpfad erstellen
        const line = d3
            .line()
            .x(d => x(d[xAxisLabel]))
            .y(d => y(d[yAxisLabel]));

        svg
            .append("path")
            .datum(data)
            .attr("fill", "none")
            .attr("stroke", "steelblue")
            .attr("stroke-width", 1.5)
            .attr("d", line);
    } catch (error) {
        console.error("Fehler beim Laden der CSV-Daten: ", error);
    }
}

// Event-Listener für Dropdowns
function initVisualization() {
    document.getElementById("alogrithmSelect").addEventListener("change", loadTimeFinal);

    // Initiale Visualisierung
    loadTimeFinal();
}

// Initialisierung bei Seitenlade
document.addEventListener("DOMContentLoaded", initVisualization);