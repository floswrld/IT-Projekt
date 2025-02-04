/**
 * Function to handle errors.
 * Logs the error and can be extended to display UI feedback.
 * @param {string} message - The error message to handle.
 */
function handleError(message) {
    console.error(message);
    // Add UI error handling logic here if needed
}


/**
 * Utility function to debounce function execution.
 * @param {Function} func - The function to debounce.
 * @param {number} wait - The debounce delay in milliseconds.
 * @returns {Function} Debounced function.
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function toggleDarkMode() {
    document.documentElement.classList.toggle('dark-mode');
    const isDarkMode = document.documentElement.classList.contains('dark-mode');
    localStorage.setItem('darkMode', isDarkMode);
    console.log('Dark Mode:', isDarkMode); // Überprüfen, ob der Zustand korrekt gespeichert wird
}

async function exportToPDF() {
    // Show loading overlay
    const loadingOverlay = document.getElementById('loadingOverlay');
    loadingOverlay.style.display = 'flex';

    try {
        const { jsPDF } = window.jspdf;
        const pdf = new jsPDF('p', 'mm', 'a4'); // Create a PDF in DIN-A4 format
        const pageWidth = 210; // Page width in mm
        const pageHeight = 297; // Page height in mm
        const margin = 10;
        let yPosition = margin; // Starting position on the page

        // Add title and description
        pdf.setFont('helvetica', 'bold');
        pdf.setFontSize(16);
        pdf.text('Information Visualisation Software', pageWidth / 2, yPosition, { align: 'center' });
        yPosition += 10;

        pdf.setFont('helvetica', 'normal');
        pdf.setFontSize(12);
        pdf.text('WIP', pageWidth / 2, yPosition, { align: 'center' });
        yPosition += 10;

        // Export charts as images
        const vizGrid = document.querySelector('.viz-grid');
        const vizContainers = vizGrid.querySelectorAll('.viz-container');

        for (const container of vizContainers) {
            // Convert chart to image using html2canvas
            const canvas = await html2canvas(container);
            const imgData = canvas.toDataURL('image/png');

            // Calculate image dimensions and aspect ratio
            const imgWidth = pageWidth - 2 * margin;
            const imgHeight = (canvas.height / canvas.width) * imgWidth;

            // Add a new page if there's not enough space
            if (yPosition + imgHeight > pageHeight - margin) {
                pdf.addPage();
                yPosition = margin;
            }

            // Add chart title
            const title = container.querySelector('.viz-title').textContent;
            pdf.setFont('helvetica', 'bold');
            pdf.setFontSize(14);
            pdf.text(title, margin, yPosition + 5);
            yPosition += 10;

            // Add the chart image
            pdf.addImage(imgData, 'PNG', margin, yPosition, imgWidth, imgHeight);
            yPosition += imgHeight + 10;
        }

        // Add footer note
        pdf.setFont('helvetica', 'italic');
        pdf.setFontSize(10);
        pdf.text(
            'This PDF was generated using the Information Visualisation Software.',
            pageWidth / 2,
            pageHeight - margin,
            { align: 'center' }
        );

        // Save the PDF file
        pdf.save('PostQuantum_Analysis.pdf');
    } catch (error) {
        console.error('Error during PDF export:', error);
        alert('An error occurred during the export. Please try again.');
    } finally {
        // Hide loading overlay
        loadingOverlay.style.display = 'none';
    }
}