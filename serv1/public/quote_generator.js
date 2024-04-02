document.getElementById('quoteForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const prompt = document.getElementById('prompt').value;
    const data = { prompt: prompt };

    fetch('/generate-quote', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
        credentials: 'include' // Ensure credentials are included for session handling
    })
    .then(response => response.json())
    .then(data => {
        if (data.message && data.continue) {
            // This means the user has exceeded their free API call limit
            alert(data.message); // Alert the user, but you might want to handle this more gracefully
            document.getElementById('quote').textContent = 'Your quote would appear here, but you have exceeded your free API calls.';
        } else {
            // Display the quote as usual
            document.getElementById('quote').textContent = data.quote;
        }
    })
    .catch((error) => {
        console.error('Error:', error);
        document.getElementById('quote').textContent = 'Error generating quote.';
    });
});
