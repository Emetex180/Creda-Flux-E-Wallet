// Banking System JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Auto-hide flash messages after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Format currency inputs
    const currencyInputs = document.querySelectorAll('input[type="number"]');
    currencyInputs.forEach(input => {
        input.addEventListener('blur', function() {
            if (this.value) {
                this.value = parseFloat(this.value).toFixed(2);
            }
        });
    });

    // PIN input validation
    const pinInputs = document.querySelectorAll('input[name="pin"]');
    pinInputs.forEach(input => {
        input.addEventListener('input', function() {
            this.value = this.value.replace(/\D/g, '').slice(0, 4);
        });
    });

    // Account number formatting
    const accountInputs = document.querySelectorAll('input[placeholder*="account"]');
    accountInputs.forEach(input => {
        input.addEventListener('input', function() {
            // Remove any existing spaces for processing
            let value = this.value.replace(/\s/g, '');
            
            // Add spaces for HUF IBAN format
            if (value.startsWith('HU') && value.length > 4) {
                value = value.replace(/(HU.{2})(.{3})(.{4})(.{16})/, '$1 $2 $3 $4');
            }
            
            this.value = value;
        });
    });

    // Balance validation for transfer form
    const amountInput = document.getElementById('amount');
    if (amountInput) {
        amountInput.addEventListener('input', function() {
            const maxAmount = parseFloat(this.max);
            const currentAmount = parseFloat(this.value);
            
            if (currentAmount > maxAmount) {
                this.setCustomValidity(`Amount cannot exceed ${maxAmount}`);
            } else {
                this.setCustomValidity('');
            }
        });
    }

    // Enhanced search functionality
    const searchInputs = document.querySelectorAll('#recipient-search');
    searchInputs.forEach(input => {
        let debounceTimer;
        
        input.addEventListener('input', function() {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                // Trigger search (handled in individual templates)
            }, 300);
        });
    });

    // Print receipt functionality
    const printButtons = document.querySelectorAll('[onclick*="print"]');
    printButtons.forEach(button => {
        button.addEventListener('click', function() {
            setTimeout(() => {
                window.print();
            }, 500);
        });
    });

    // Security: Clear form data on page leave
    window.addEventListener('beforeunload', function() {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            if (form.querySelector('input[type="password"]')) {
                form.reset();
            }
        });
    });

    // Add loading states to all forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = this.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                const originalText = submitBtn.innerHTML;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
                
                // Re-enable button after 30 seconds (safety measure)
                setTimeout(() => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;
                }, 30000);
            }
        });
    });

    // Enhanced user experience: Smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Real-time balance update simulation
    function updateBalanceDisplay() {
        const balanceElements = document.querySelectorAll('.balance-amount, .balance-display');
        balanceElements.forEach(element => {
            // In a real application, this would fetch from the server
            console.log('Balance display updated');
        });
    }

    // Simulate live updates every 30 seconds
    setInterval(updateBalanceDisplay, 30000);
});

// Utility functions
const BankUtils = {
    formatCurrency: (amount, currency) => {
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: currency
        }).format(amount);
    },

    formatAccountNumber: (accountNumber) => {
        if (accountNumber.startsWith('HU')) {
            return accountNumber.replace(/(HU.{2})(.{3})(.{4})(.{16})/, '$1 $2 $3 $4');
        }
        return accountNumber;
    },

    validatePIN: (pin) => {
        return /^\d{4}$/.test(pin);
    },

    calculateExchange: (amount, fromCurrency, toCurrency) => {
        const rates = {
            'HUF_TO_USD': 0.0028,
            'USD_TO_HUF': 357.14
        };
        
        if (fromCurrency === 'HUF' && toCurrency === 'USD') {
            return amount * rates.HUF_TO_USD;
        } else if (fromCurrency === 'USD' && toCurrency === 'HUF') {
            return amount * rates.USD_TO_HUF;
        }
        return amount;
    }
};