const form = document.getElementById('generateForm');
const generateBtn = document.getElementById('generateBtn');
const textOutput = document.getElementById('textOutput');
const generatedText = document.getElementById('generatedText');
const copyBtn = document.getElementById('copyBtn');
const remainingTokens = document.getElementById('remainingTokens');
const templateCards = document.querySelectorAll('.template-card');
const historyButtons = document.querySelectorAll('.copy-history-btn');

// Şablon seçimi
templateCards.forEach(card => {
    card.addEventListener('click', () => {
        templateCards.forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
    });
});

// Metin kopyalama
function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('Metin kopyalandı!');
    }).catch(err => {
        console.error('Kopyalama hatası:', err);
    });
}

// Yeni oluşturulan metin için kopyalama
copyBtn.addEventListener('click', () => {
    copyText(generatedText.innerText);
});

// Geçmiş metinler için kopyalama
historyButtons.forEach(button => {
    button.addEventListener('click', () => {
        const content = button.dataset.content;
        copyText(content);
    });
});

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = new FormData(form);
    formData.append('template', document.querySelector('.template-card.selected').dataset.template);
    
    generateBtn.disabled = true;
    generateBtn.querySelector('.normal').classList.add('hidden');
    generateBtn.querySelector('.loading').classList.remove('hidden');
    
    try {
        const response = await fetch('/generate-text', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            textOutput.classList.remove('hidden');
            generatedText.innerHTML = data.text;
            
            remainingTokens.textContent = data.remaining_tokens === 'Sınırsız' ? 
                '∞' : data.remaining_tokens;
        } else {
            alert(data.error || 'Bir hata oluştu');
        }
    } catch (error) {
        console.error('Hata:', error);
        alert('Bir hata oluştu');
    } finally {
        generateBtn.disabled = false;
        generateBtn.querySelector('.normal').classList.remove('hidden');
        generateBtn.querySelector('.loading').classList.add('hidden');
    }
}); 