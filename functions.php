<?php

/* --- Setup ---
   INCLUDE NECESSARY PLUGIN FILES
----------------------------------------------- */
require_once wp_normalize_path(WP_PLUGIN_DIR . '/bp-better-messages-websocket/inc/users.php');

/* --- Function formulaire_connexion_shortcode ---
   SHORTCODE FORM
----------------------------------------------- */
function formulaire_connexion_shortcode() {
    // Check if user is logged in - return empty if they are
    if (is_user_logged_in()) {
        return '';
    }

    ob_start();
    // Add nonce field for security
    wp_nonce_field('form_connexion_action', 'form_connexion_nonce');
    ?>
    <!-- Début du formulaire -->
    <div class="formcoco" style="position: relative;">
        <div id="invitea">
            <style>
                /* Styles pour le formulaire encapsulés sous #invitea */
                #invitea {
                    position: relative; 
                    width: 100vw;
                    min-width: 180px;
                    max-width: 260px;
                    height: 100vw;
                    min-height: 230px;
                    max-height: 260px;
                    left: 100px;
                    top: 0px;
                    color: rgb(0, 0, 0);
                    background-color: rgb(165, 177, 197);
                    font-size: min(15px, 6vw) !important;
                    z-index: 60;
                    font-family: Verdana !important;
                    font-weight: bold !important;
                    border: 1px solid rgb(90, 74, 66);
                }

                #invitea input[type="text"],
                #invitea input[type="tel"] {
                    height: 27px;
                    padding: 5px;
                    border: 1px solid #000;
                    border-radius: 5px;
                    width: 82%;
                }

                #invitea input[type="radio"] {
                    margin-right: 10px;
                }

                #invitea .souligne {
                    text-decoration: underline;
                    cursor: pointer;
                    display: inline-block;
                }

                #invitea #entry {
                    position: absolute;
                    width: 85px;
                    height: 15%;
                    color: #000;
                    line-height: 2em;
                    text-align: center;
                    bottom: 7%;
                    right: 7%;
                    cursor: pointer;
                    user-select: none;
                    background-color: #f0c674;
                    border-radius: 5px;
                    border: 1px solid #000;
                }

                #invitea #deroulante {
                    position: absolute;
                    font-weight: bold;
                    left: 20px;
                    top: 100px;
                    z-index: 17;
                    visibility: hidden;
                    border: solid;
                    border-width: 1px;
                    background-color: #fff;
                    overflow: auto;
                }

                #invitea .desktop {
                    position: absolute;
                    left: calc(15% - 350px);
                    top: 0px;
                    width: 300px;
                    height: 280px;
                }

                #invitea .no-break {
                    white-space: nowrap;
                }
            </style>

            <!-- Form fields with improved validation -->
            <div style="position:absolute;left:75px;top:5px;">Pseudo</div>
            <input type="text" id="nicko" minlength="4" maxlength="16" onkeypress="checar(event)" pattern="[A-Za-z0-9]+" required value="" style="position:absolute;user-select: none; top:24px;left:7%; font-weight: bold;">

            <div style="position:absolute;left:15%;top:25%;">
                <form name="discuform">
                    <div style="display: flex; align-items: center;">
                        <input id="mano" type="radio" name="typeo" value="Homme" style="margin-right: 5px;" required>
                        <label for="mano" class="souligne" style="color: black;">Homme</label>

                        <input id="femme" type="radio" name="typeo" value="Femme" style="margin-left: 20px; margin-right: 5px;">
                        <label for="femme" class="souligne" style="color: black;">Femme</label>
                    </div>
                    
                    <div style="margin-top: 10px;">
                        <input id="travtrans" type="radio" name="typeo" value="Trans/Trav" style="margin-right: 5px;">
                        <label for="travtrans" class="souligne" style="color: black;">Trans/Trav</label>
                    </div>
                </form>
            </div>

            <div style="position:absolute;left:30%;top:55%; display: flex; align-items: center;">Age
                <input type="tel" id="ageu" maxlength="2" value="" oninput="checkAge()" style="width: 40px; margin-left: 10px; font-weight: bold; text-transform: uppercase;">
            </div>

            <div id="zipoa" style="position:absolute;left:20px;top:70%;">Code Postal<br>
                <input type="tel" id="zipo" value="" style="position: relative; width: 60px; left: 10px; top: 3px; font-weight: bold; text-transform: uppercase;" onkeyup="getCommune();">
                <div id="commune" style="margin-top: 5px; font-weight: bold; text-transform: uppercase;"></div>
            </div>

            <div id="deroulante" style="position:absolute; font-weight: bold; left: 20px; top: 80%; z-index: 17; visibility: hidden; border: solid; border-width: 1px; background-color: #fff; overflow: auto;"></div>

            <div id="entry" onclick="validatio();">Entrée</div>
        </div>
    </div>

    <script>
    // Input validation functions
    function checar(e) {
        // Allow only alphanumeric characters
        const char = String.fromCharCode(e.keyCode);
        const regex = /[A-Za-z0-9]/;
        if (!regex.test(char)) {
            e.preventDefault();
            return false;
        }
        return true;
    }

    function checkAge() {
        const ageInput = document.getElementById('ageu');
        let value = ageInput.value;
        
        // Remove non-numeric characters
        value = value.replace(/[^0-9]/g, '');
        
        // Ensure age is between 18 and 99
        if (value.length > 0) {
            const age = parseInt(value);
            if (age < 18) value = '18';
            if (age > 99) value = '99';
        }
        
        ageInput.value = value;
    }

    async function getCommune() {
        const zipoInput = document.getElementById('zipo');
        const communeDiv = document.getElementById('commune');
        const value = zipoInput.value.replace(/[^0-9]/g, '');
        
        if (value.length === 5) {
            try {
                const response = await fetch('YOUR_API_ENDPOINT');
                const data = await response.json();
                if (data.commune) {
                    communeDiv.textContent = data.commune;
                }
            } catch (err) {
                console.error('Error fetching commune:', err);
            }
        }
        zipoInput.value = value;
    }

    function validatio() {
        // Get form values
        const nickname = document.getElementById('nicko').value;
        const gender = document.querySelector('input[name="typeo"]:checked')?.value;
        const age = document.getElementById('ageu').value;
        const zipCode = document.getElementById('zipo').value;
        
        // Validate required fields
        if (!nickname || nickname.length < 4) {
            alert('Le pseudo doit contenir au moins 4 caractères');
            return;
        }
        
        if (!gender) {
            alert('Veuillez sélectionner votre genre');
            return;
        }
        
        if (!age || parseInt(age) < 18) {
            alert('Vous devez avoir au moins 18 ans');
            return;
        }
        
        if (!zipCode || zipCode.length !== 5) {
            alert('Le code postal doit contenir 5 chiffres');
            return;
        }

        // Get the nonce value
        const nonce = document.querySelector('[name="form_connexion_nonce"]').value;
        
        // Prepare form data
        const formData = new FormData();
        formData.append('action', 'form_connexion_submit');
        formData.append('nickname', nickname);
        formData.append('gender', gender);
        formData.append('age', age);
        formData.append('zipCode', zipCode);
        formData.append('nonce', nonce);
        
        // Submit form
        fetch(ajaxurl, {
            method: 'POST',
            credentials: 'same-origin',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.reload();
            } else {
                alert(data.data || 'Une erreur est survenue');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Une erreur est survenue');
        });
    }
    </script>
    <?php
    return ob_get_clean();
}
add_shortcode('formulaire_connexion', 'formulaire_connexion_shortcode');

/* --- Function formulaire_connexion_scripts ---
   CHARGER LES SCRIPTS JS ET FICHIER JSON
----------------------------------------------- */
function formulaire_connexion_scripts() {
    if (is_singular() && has_shortcode(get_post()->post_content, 'formulaire_connexion')) {
        wp_enqueue_script(
            'script-ville',
            get_stylesheet_directory_uri() . '/scriptville.js',
            array('jquery'),
            null,
            true
        );

        wp_localize_script(
            'script-ville',
            'formulaireParams',
            array(
                'ajaxurl' => admin_url('admin-ajax.php'),
                'jsonUrl' => get_stylesheet_directory_uri() . '/communes.json',
                'nonce' => wp_create_nonce('form_connexion_ajax')
            )
        );
    }
}
add_action('wp_enqueue_scripts', 'formulaire_connexion_scripts');

/* --- Function handle_form_submission ---
   HANDLE FORM SUBMISSION
----------------------------------------------- */
function handle_form_submission() {
    // Verify nonce
    if (!check_ajax_referer('form_connexion_ajax', 'nonce', false)) {
        wp_send_json_error('Invalid nonce');
    }

    // Validate and sanitize inputs
    $nickname = isset($_POST['nickname']) ? sanitize_text_field($_POST['nickname']) : '';
    $gender = isset($_POST['gender']) ? sanitize_text_field($_POST['gender']) : '';
    $age = isset($_POST['age']) ? intval($_POST['age']) : 0;
    $zipCode = isset($_POST['zipCode']) ? sanitize_text_field($_POST['zipCode']) : '';

    // Validation
    if (strlen($nickname) < 4 || strlen($nickname) > 16) {
        wp_send_json_error('Invalid nickname length');
    }

    if (!in_array($gender, array('Homme', 'Femme', 'Trans/Trav'))) {
        wp_send_json_error('Invalid gender');
    }

    if ($age < 18 || $age > 99) {
        wp_send_json_error('Invalid age');
    }

    if (!preg_match('/^\d{5}$/', $zipCode)) {
        wp_send_json_error('Invalid zip code');
    }

    // Process form submission
    try {
        // Your form processing logic here
        // ...

        wp_send_json_success('Form submitted successfully');
    } catch (Exception $e) {
        wp_send_json_error('Error processing form: ' . $e->getMessage());
    }
}
add_action('wp_ajax_form_connexion_submit', 'handle_form_submission');
add_action('wp_ajax_nopriv_form_connexion_submit', 'handle_form_submission');