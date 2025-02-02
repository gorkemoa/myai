document.addEventListener('DOMContentLoaded', function() {
    // Favori butonlarını dinle
    document.querySelectorAll('.favorite-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const imageId = this.dataset.imageId;
            toggleFavorite(imageId, this);
        });
    });
    
    // Modal görüntüleme
    document.querySelectorAll('.gallery-item img').forEach(img => {
        img.addEventListener('click', function() {
            const modal = document.getElementById('imageModal');
            const modalImg = document.getElementById('modalImage');
            const modalPrompt = document.getElementById('modalPrompt');
            
            modalImg.src = this.src;
            modalPrompt.textContent = this.dataset.prompt;
            modal.style.display = 'block';
        });
    });
    
    // Modal kapatma
    document.querySelector('.modal .close').addEventListener('click', function() {
        document.getElementById('imageModal').style.display = 'none';
    });
});

async function toggleFavorite(imageId, button) {
    try {
        const response = await fetch('/toggle-favorite', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ image_id: imageId })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Favori durumunu güncelle
            button.classList.toggle('favorited');
            button.querySelector('i').classList.toggle('fas');
            button.querySelector('i').classList.toggle('far');
            
            // Bildirim göster
            showNotification(data.message, 'success');
        } else {
            showNotification(data.error || 'Bir hata oluştu', 'error');
        }
    } catch (error) {
        console.error('Favori işlemi sırasında hata:', error);
        showNotification('Bir hata oluştu', 'error');
    }
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // 3 saniye sonra kaldır
    setTimeout(() => {
        notification.remove();
    }, 3000);
} 