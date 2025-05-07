// Example of a simple admin notice dismissal (you can add more interactivity here as needed)
jQuery(document).ready(function($){
    // Hide the admin notice after clicking the dismiss button
    $('.notice-dismiss').on('click', function(){
        // You can add an AJAX request here to log the dismissal if needed
        console.log('Notice dismissed');
    });

    // Example of toggling a setting or showing/hiding an element based on checkbox selection
    $('#security_email_alerts').on('change', function() {
        if ($(this).is(':checked')) {
            alert('Email alerts are enabled.');
        } else {
            alert('Email alerts are disabled.');
        }
    });
});
