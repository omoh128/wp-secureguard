/**
 * Security Plugin Admin JavaScript
 * 
 * Handles all interactive features of the security plugin admin interface
 */
(function($) {
    'use strict';

    // Initialize when DOM is ready
    $(document).ready(function() {
        SecurityAdmin.init();
    });

    // Main object to handle all admin functionality
    var SecurityAdmin = {
        
        // Initialize all functionality
        init: function() {
            this.setupIPBlocking();
            this.setupLogRefresh();
            this.setupSecurityDashboard();
            this.setupRealTimeStats();
            this.setupNotificationSettings();
        },

        // Handle IP blocking functionality
        setupIPBlocking: function() {
            // IP validation for the block IP form
            $('#ip_address').on('input', function() {
                const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
                const ip = $(this).val();
                
                if (ip && !ipRegex.test(ip)) {
                    $(this).addClass('invalid-ip');
                    $('#block-ip-submit').prop('disabled', true);
                } else {
                    $(this).removeClass('invalid-ip');
                    $('#block-ip-submit').prop('disabled', false);
                }
            });

            // Confirm unblock action with a dialog
            $('.unblock-ip-btn').on('click', function(e) {
                if (!confirm('Are you sure you want to unblock this IP address?')) {
                    e.preventDefault();
                }
            });

            // Bulk actions for IP management
            $('#bulk-action-submit').on('click', function(e) {
                const action = $('#bulk-action-selector').val();
                if (action === '-1') {
                    alert('Please select an action to perform');
                    e.preventDefault();
                    return;
                }

                const checkedIps = $('.ip-checkbox:checked').length;
                if (checkedIps === 0) {
                    alert('Please select at least one IP address');
                    e.preventDefault();
                    return;
                }

                if (action === 'unblock' && !confirm('Are you sure you want to unblock the selected IP addresses?')) {
                    e.preventDefault();
                }
            });
        },

        // Handle log refresh functionality
        setupLogRefresh: function() {
            // Auto-refresh logs on log viewer pages
            if ($('.log-viewer-container').length > 0) {
                const refreshLogs = function() {
                    const container = $('.log-viewer-container');
                    const logType = container.data('log-type');
                    const spinner = $('#log-refresh-spinner');
                    
                    spinner.show();
                    
                    $.ajax({
                        url: securityAdminData.ajaxUrl,
                        type: 'POST',
                        data: {
                            action: 'refresh_security_logs',
                            log_type: logType,
                            nonce: securityAdminData.nonce
                        },
                        success: function(response) {
                            if (response.success) {
                                container.find('pre').html(response.data.log_content);
                                $('#last-refreshed').text(response.data.timestamp);
                            } else {
                                console.error('Error refreshing logs:', response.data.message);
                            }
                            spinner.hide();
                        },
                        error: function(xhr, status, error) {
                            console.error('AJAX error:', error);
                            spinner.hide();
                        }
                    });
                };

                // Refresh button click handler
                $('#refresh-logs').on('click', function() {
                    refreshLogs();
                });

                // Auto-refresh every 60 seconds if enabled
                if ($('#auto-refresh').is(':checked')) {
                    let refreshInterval = setInterval(refreshLogs, 60000);
                    
                    // Toggle auto-refresh
                    $('#auto-refresh').on('change', function() {
                        if ($(this).is(':checked')) {
                            refreshInterval = setInterval(refreshLogs, 60000);
                        } else {
                            clearInterval(refreshInterval);
                        }
                    });
                }
            }
        },

        // Setup security dashboard widgets
        setupSecurityDashboard: function() {
            if ($('#security-dashboard').length > 0) {
                // Initialize charts if Chart.js is available
                if (typeof Chart !== 'undefined') {
                    // Failed login attempts chart
                    const loginAttemptsCtx = document.getElementById('login-attempts-chart').getContext('2d');
                    new Chart(loginAttemptsCtx, {
                        type: 'line',
                        data: {
                            labels: securityAdminData.loginStats.labels,
                            datasets: [{
                                label: 'Failed Login Attempts',
                                data: securityAdminData.loginStats.failed,
                                borderColor: 'rgba(255, 99, 132, 1)',
                                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                                tension: 0.4
                            }, {
                                label: 'Successful Logins',
                                data: securityAdminData.loginStats.successful,
                                borderColor: 'rgba(54, 162, 235, 1)',
                                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                                tension: 0.4
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    title: {
                                        display: true,
                                        text: 'Count'
                                    }
                                }
                            }
                        }
                    });

                    // Firewall events chart
                    const firewallEventsCtx = document.getElementById('firewall-events-chart').getContext('2d');
                    new Chart(firewallEventsCtx, {
                        type: 'bar',
                        data: {
                            labels: securityAdminData.firewallStats.labels,
                            datasets: [{
                                label: 'Blocked Requests',
                                data: securityAdminData.firewallStats.data,
                                backgroundColor: 'rgba(255, 159, 64, 0.7)'
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    title: {
                                        display: true,
                                        text: 'Count'
                                    }
                                }
                            }
                        }
                    });
                }

                // Initialize security score donut chart
                this.updateSecurityScore();
                
                // Run security scan button
                $('#run-security-scan').on('click', function() {
                    const scanButton = $(this);
                    const originalText = scanButton.text();
                    const resultsContainer = $('#scan-results');
                    
                    scanButton.text('Scanning...').prop('disabled', true);
                    resultsContainer.html('<p>Scanning your site for security issues...</p>');
                    
                    $.ajax({
                        url: securityAdminData.ajaxUrl,
                        type: 'POST',
                        data: {
                            action: 'run_security_scan',
                            nonce: securityAdminData.nonce
                        },
                        success: function(response) {
                            scanButton.text(originalText).prop('disabled', false);
                            if (response.success) {
                                resultsContainer.html(response.data.results_html);
                                SecurityAdmin.updateSecurityScore();
                            } else {
                                resultsContainer.html('<p class="error">Error: ' + response.data.message + '</p>');
                            }
                        },
                        error: function(xhr, status, error) {
                            scanButton.text(originalText).prop('disabled', false);
                            resultsContainer.html('<p class="error">Error: Could not complete the scan. Please try again.</p>');
                            console.error('AJAX error:', error);
                        }
                    });
                });
            }
        },

        // Update security score visualization
        updateSecurityScore: function() {
            if ($('#security-score-chart').length > 0 && typeof Chart !== 'undefined') {
                const scoreCtx = document.getElementById('security-score-chart').getContext('2d');
                const score = parseInt($('#security-score').data('score'));
                
                new Chart(scoreCtx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Secure', 'Needs Improvement'],
                        datasets: [{
                            data: [score, 100 - score],
                            backgroundColor: [
                                score >= 80 ? '#4CAF50' : (score >= 50 ? '#FFC107' : '#F44336'),
                                '#E0E0E0'
                            ],
                            borderWidth: 0
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        cutout: '75%',
                        plugins: {
                            legend: {
                                display: false
                            },
                            tooltip: {
                                enabled: false
                            }
                        }
                    }
                });
                
                // Update the score text
                $('#security-score-value').text(score);
                
                // Update the security status text
                let statusText = 'Poor';
                let statusClass = 'poor';
                
                if (score >= 80) {
                    statusText = 'Good';
                    statusClass = 'good';
                } else if (score >= 50) {
                    statusText = 'Fair';
                    statusClass = 'fair';
                }
                
                $('#security-status')
                    .text(statusText)
                    .removeClass('good fair poor')
                    .addClass(statusClass);
            }
        },

        // Setup real-time stats functionality
        setupRealTimeStats: function() {
            if ($('#security-realtime-stats').length > 0) {
                const updateStats = function() {
                    $.ajax({
                        url: securityAdminData.ajaxUrl,
                        type: 'POST',
                        data: {
                            action: 'get_realtime_security_stats',
                            nonce: securityAdminData.nonce
                        },
                        success: function(response) {
                            if (response.success) {
                                const data = response.data;
                                
                                // Update stats counters
                                $('#current-visitors').text(data.current_visitors);
                                $('#blocked-requests').text(data.blocked_requests);
                                $('#failed-logins').text(data.failed_logins);
                                $('#suspicious-activities').text(data.suspicious_activities);
                                
                                // Update active threats list if available
                                if (data.active_threats && data.active_threats.length > 0) {
                                    let threatHtml = '';
                                    $.each(data.active_threats, function(i, threat) {
                                        threatHtml += '<div class="threat-item ' + threat.severity + '">';
                                        threatHtml += '<span class="threat-time">' + threat.time + '</span>';
                                        threatHtml += '<span class="threat-type">' + threat.type + '</span>';
                                        threatHtml += '<span class="threat-ip">' + threat.ip + '</span>';
                                        threatHtml += '<span class="threat-details">' + threat.details + '</span>';
                                        threatHtml += '</div>';
                                    });
                                    $('#active-threats').html(threatHtml);
                                } else {
                                    $('#active-threats').html('<p>No active threats detected.</p>');
                                }
                            }
                        }
                    });
                };
                
                // Update stats immediately and then every 30 seconds
                updateStats();
                setInterval(updateStats, 30000);
            }
        },

        // Setup notification settings
        setupNotificationSettings: function() {
            // Toggle email notification settings visibility
            $('#security_email_alerts').on('change', function() {
                if ($(this).is(':checked')) {
                    $('#email-notification-settings').slideDown();
                } else {
                    $('#email-notification-settings').slideUp();
                }
            }).trigger('change');
            
            // Test email notification
            $('#test-email-notification').on('click', function() {
                const button = $(this);
                const originalText = button.text();
                
                button.text('Sending...').prop('disabled', true);
                
                $.ajax({
                    url: securityAdminData.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'test_security_email',
                        nonce: securityAdminData.nonce
                    },
                    success: function(response) {
                        button.text(originalText).prop('disabled', false);
                        
                        if (response.success) {
                            alert('Test email sent successfully! Please check your inbox.');
                        } else {
                            alert('Error: ' + response.data.message);
                        }
                    },
                    error: function() {
                        button.text(originalText).prop('disabled', false);
                        alert('Error: Could not send test email. Please try again.');
                    }
                });
            });
            
            // Toggle SMS notifications settings
            $('#enable_sms_notifications').on('change', function() {
                if ($(this).is(':checked')) {
                    $('#sms-notification-settings').slideDown();
                } else {
                    $('#sms-notification-settings').slideUp();
                }
            }).trigger('change');
        }
    };

})(jQuery);
