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
                    left: 100px; /* Ajuste comme nécessaire */
                    top: 0px; /* Ajuste comme nécessaire */
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

            <div style="position:absolute;left:75px;top:5px;">Pseudo</div>
            <input type="text" id="nicko" minlength="4" maxlength="16" onkeypress="return checar(event)" value="" style="position:absolute;user-select: none; top:24px;left:7%; font-weight: bold;">

            <div style="position:absolute;left:15%;top:25%;">
                <form name="discuform">
                    <div style="display: flex; align-items: center;">
                        <input id="mano" type="radio" name="typeo" value="Homme" style="margin-right: 5px;">
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
    <!-- Fin du formulaire -->
    <?php
    return ob_get_clean();
}
add_shortcode('formulaire_connexion', 'formulaire_connexion_shortcode');



/* --- Function formulaire_connexion_scripts ---
   CHARGER LES SCRIPTS JS ET FICHIER JSON
----------------------------------------------- */
function formulaire_connexion_scripts() {
    // Vérifie si le shortcode est utilisé sur la page
    if ( is_singular() && has_shortcode( get_post()->post_content, 'formulaire_connexion' ) ) {
        // Enqueue le script JavaScript
        wp_enqueue_script(
            'script-ville', // Handle
            get_stylesheet_directory_uri() . '/scriptville.js', // Source
            array(), // Dépendances
            null, // Version
            true // En bas de page (footer)
        );

        // Passe l'URL du fichier JSON au script JavaScript
        wp_localize_script(
            'script-ville',
            'formulaireParams',
            array(
                'jsonUrl' => get_stylesheet_directory_uri() . '/communes.json'
            )
        );
    }
}
add_action('wp_enqueue_scripts', 'formulaire_connexion_scripts');



/* --- Function custom_format_city_field ---
   SANITIZATION DE VILLE POUR XPROFILE
----------------------------------------------- */
function custom_format_city_field( $value, $data_id, $reserialize, $profile_data ) {
    // Check if the field ID is 17 (the city field)
    if ( $profile_data->field_id == 17 ) {
        // Convert accented characters to their basic counterparts
        if ( function_exists( 'transliterator_transliterate' ) ) {
            $value = transliterator_transliterate( 'Any-Latin; Latin-ASCII', $value );
        } else {
            // Fallback: Replace manually if transliterator is unavailable
            $value = str_replace(
                ['À', 'Á', 'Â', 'Ã', 'Ä', 'Å', 'Æ', 'Ç', 'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î', 'Ï', 'Ð', 'Ñ', 'Ò', 'Ó', 'Ô', 'Õ', 'Ö', 'Ø', 'Ù', 'Ú', 'Û', 'Ü', 'Ý', 'Þ', 'ß', 'à', 'á', 'â', 'ã', 'ä', 'å', 'æ', 'ç', 'è', 'é', 'ê', 'ë', 'ì', 'í', 'î', 'ï', 'ð', 'ñ', 'ò', 'ó', 'ô', 'õ', 'ö', 'ø', 'ù', 'ú', 'û', 'ü', 'ý', 'þ', 'ÿ'],
                ['A', 'A', 'A', 'A', 'A', 'A', 'AE', 'C', 'E', 'E', 'E', 'E', 'I', 'I', 'I', 'I', 'D', 'N', 'O', 'O', 'O', 'O', 'O', 'O', 'U', 'U', 'U', 'U', 'Y', 'TH', 'ss', 'a', 'a', 'a', 'a', 'a', 'a', 'ae', 'c', 'e', 'e', 'e', 'e', 'i', 'i', 'i', 'i', 'd', 'n', 'o', 'o', 'o', 'o', 'o', 'o', 'u', 'u', 'u', 'u', 'y', 'th', 'y'],
                $value
            );
        }

        // Replace hyphens and apostrophes with spaces
        $value = str_replace( ['-', "'"], ' ', $value );
        
        // Remove any digits or special characters except letters and spaces
        $value = preg_replace('/[^A-Za-z\s]/', '', $value);
        
        // Convert to uppercase
        $value = strtoupper( $value );
        
        // Replace multiple spaces with a single space
        $value = preg_replace('/\s+/', ' ', $value);

        // Trim spaces from both ends
        $value = trim( $value );
        
        // Truncate if longer than 25 characters
        if (strlen($value) > 25) {
            $value = substr($value, 0, 25);
        }
    }

    return $value;
}
add_filter( 'xprofile_data_value_before_save', 'custom_format_city_field', 10, 4 );



/* --- Function track_user_data ---
   TRACK IP AND USER AGENT FOR ALL USERS
----------------------------------------------- */
function track_user_data($user_id, $is_registration = false) {
    global $wpdb;
    $users_table = bm_get_table('users');
    
    // Get IP address
    $ip = '';
    if (isset($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = sanitize_text_field($_SERVER['HTTP_CLIENT_IP']);
    } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = sanitize_text_field($_SERVER['HTTP_X_FORWARDED_FOR']);
    } elseif (isset($_SERVER['REMOTE_ADDR'])) {
        $ip = sanitize_text_field($_SERVER['REMOTE_ADDR']);
    }
    
    // Get user agent
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : '';
    
    // For regular WordPress users
    if ($user_id > 0) {
        // Store in user meta for backup
        if ($is_registration) {
            update_user_meta($user_id, 'registration_ip', $ip);
        }
        update_user_meta($user_id, 'last_ip', $ip);
        update_user_meta($user_id, 'user_agent', $user_agent);
        
        // Update the users table
        $wpdb->query($wpdb->prepare(
            "INSERT INTO $users_table (ID, ip, user_agent) 
             VALUES (%d, %s, %s)
             ON DUPLICATE KEY UPDATE ip = VALUES(ip), user_agent = VALUES(user_agent)",
            $user_id,
            $ip,
            $user_agent
        ));
    } 
    // For guest users
    else {
        $guest_id = abs($user_id);
        $guests_table = bm_get_table('guests');
        
        // Update guests table
        $wpdb->query($wpdb->prepare(
            "UPDATE $guests_table 
             SET ip = %s, user_agent = %s 
             WHERE id = %d",
            $ip,
            $user_agent,
            $guest_id
        ));
        
        // Update users index table
        $wpdb->query($wpdb->prepare(
            "INSERT INTO $users_table (ID, ip, user_agent) 
             VALUES (%d, %s, %s)
             ON DUPLICATE KEY UPDATE ip = VALUES(ip), user_agent = VALUES(user_agent)",
            $user_id,  // This is already negative
            $ip,
            $user_agent
        ));
    }
    
    // Clear any cached user data
    wp_cache_delete('guest_user_' . abs($user_id), 'bm_messages');
    
    // Trigger user updated action
    do_action('better_messages_user_updated', $user_id);
}

// Hook for WordPress user login
add_action('wp_login', function($user_login, $user) {
    track_user_data($user->ID, false);
}, 10, 2);

// Hook for WordPress user registration
add_action('user_register', function($user_id) {
    track_user_data($user_id, true);
}, 10, 1);

// Hook for guest registration
add_action('better_messages_guest_registered', function($guest_id) {
    track_user_data(-1 * abs($guest_id), true);
}, 10, 1);

// Hook for guest updates
add_action('better_messages_guest_updated', function($guest_id) {
    track_user_data(-1 * abs($guest_id), false);
}, 10, 1);




/* --- Function bm_add_admin_menu ---
   ADD ADMIN MENU FOR SYNC USERS WITH UPDATED NAME
----------------------------------------------- */
add_action('admin_menu', 'bm_add_admin_menu');
function bm_add_admin_menu() {
    add_menu_page(
        'Admin Sync Users', // Changed from 'Sync Users'
        'Admin Sync Users', // Changed from 'Sync Users'
        'manage_options', 
        'admin-sync-users', // Changed from 'sync-users'
        'sync_users_page'
    );
}




/* --- Function bm_lookup_ip_callback ---
   ENHANCED AJAX HANDLER FOR IP LOOKUP WITH USER STATS
----------------------------------------------- */
add_action('wp_ajax_bm_lookup_ip', 'bm_lookup_ip_callback');
function bm_lookup_ip_callback() {
    check_ajax_referer('bm_lookup_ip', 'nonce');
    
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
    }

    $ip = sanitize_text_field($_POST['ip']);
    $display_name = sanitize_text_field($_POST['display_name']);
    $user_id = intval($_POST['user_id']); 
    
    if (empty($ip)) {
        wp_send_json_error('Invalid IP address');
    }

    global $wpdb;
    
    // Get GeoIP record
    $record = geoip_detect2_get_info_from_ip($ip);
    
    // Get user stats
    $messages_table = bm_get_table('messages');
    $recipients_table = bm_get_table('recipients');
    
    // Get message stats
    $message_stats = $wpdb->get_row($wpdb->prepare("
        SELECT 
            COUNT(DISTINCT m.id) as total_messages,
            COUNT(DISTINCT r.thread_id) as total_conversations,
            MIN(m.date_sent) as first_message,
            MAX(m.date_sent) as last_message
        FROM {$messages_table} m
        LEFT JOIN {$recipients_table} r ON m.thread_id = r.thread_id
        WHERE m.sender_id = %d
    ", $user_id));

    // Get reports sent by this user
	$meta_table = bm_get_table('meta');
	$reports_sent = $wpdb->get_var($wpdb->prepare("
		SELECT COUNT(DISTINCT meta_id)
		FROM {$meta_table}
		WHERE meta_key = 'user_reports'
		AND meta_value LIKE %s",
		'%i:' . $user_id . ';a:%'  // This matches the serialized array format where user_id is the key
	));

    // Get IP usage count and associated users
    $ip_usage = $wpdb->get_results($wpdb->prepare("
        SELECT u.ID, u.display_name 
        FROM " . bm_get_table('users') . " u
        WHERE u.ip = %s
        ORDER BY u.last_activity DESC",
        $ip
    ));
    
    // Get toxicity status for each user
    $ip_users_list = array_map(function($user) {
        $toxicity_status = Better_Messages_User_Toxicity()->get_toxicity_status($user->ID);
        return sprintf(
            '%s (ID: %d) - %s %s Reliability: %.1f%%',
            $user->display_name,
            $user->ID,
            $toxicity_status['icon'],
            $toxicity_status['level'],
            $toxicity_status['percentage']
        );
    }, $ip_usage);
    
    $ip_count = count($ip_usage);

    // Calculate days active
    $days_active = 0;
    if (!empty($message_stats->first_message) && !empty($message_stats->last_message)) {
        $first_message_date = strtotime($message_stats->first_message);
        $last_message_date = strtotime($message_stats->last_message);
        $days_active = max(1, ceil(($last_message_date - $first_message_date) / (60 * 60 * 24)));
    }

    // Calculate activity metrics
    $days_active = 0;
    if (!empty($message_stats->first_message) && !empty($message_stats->last_message)) {
        $first_message_date = strtotime($message_stats->first_message);
        $last_message_date = strtotime($message_stats->last_message);
        $days_active = max(1, ceil(($last_message_date - $first_message_date) / (60 * 60 * 24)));
    }
    $days_per_message = $message_stats->total_messages > 0 ? round($days_active / $message_stats->total_messages, 2) : 0;
    
    // Get report stats
    $report_stats = $wpdb->get_results($wpdb->prepare("
        SELECT meta_value 
        FROM {$meta_table} 
        WHERE meta_key = 'user_reports' 
        AND bm_message_id IN (
            SELECT id FROM {$messages_table} WHERE sender_id = %d
        )
    ", $user_id));

    $report_categories = [
        'spam' => 0,
        'harassment' => 0,
        'offensive' => 0,
        'inappropriate' => 0,
        'other' => 0
    ];

    foreach ($report_stats as $report) {
        $reports = maybe_unserialize($report->meta_value);
        if (is_array($reports)) {
            foreach ($reports as $report_data) {
                if (isset($report_data['category'])) {
                    $report_categories[$report_data['category']]++;
                }
            }
        }
    }

    // Get toxicity status
    $toxicity_status = Better_Messages_User_Toxicity()->get_toxicity_status($user_id);

    // Check if IP is already banned
    $banned_ips = get_option('banned_ips', array());
    $is_banned = in_array($ip, $banned_ips);
    
    // Get user agent and parse device info
    $user_agent = '';
    if ($user_id > 0) {
        $user_agent = get_user_meta($user_id, 'user_agent', true);
    } else {
        $guest_id = abs($user_id);
        $user_agent = $wpdb->get_var($wpdb->prepare(
            "SELECT user_agent FROM " . bm_get_table('guests') . " WHERE id = %d",
            $guest_id
        ));
    }
    
    $device_type = get_device_type($user_agent);
    $device_icon = $device_type === 'mobile' ? '📱' : '💻';

    if ($record) {
        $html = sprintf('
            <div class="ip-lookup-results">
                <div class="lookup-header">
                    <h2>User Profile: %s</h2>
                    <button type="button" class="popup-close-btn" onclick="jQuery(\'#ip-lookup-popup\').hide();">×</button>
                </div>

                <div class="lookup-grid">
                    <!-- Location Information -->
                    <div class="lookup-section location-info">
                        <h3>Location Data</h3>
                        <div class="info-grid">
                            <div class="info-item">
                                <strong>IP Address:</strong> %s %s %s
                            </div>
                            <div class="info-item">
                                <strong>Location:</strong> %s, %s
                            </div>
                            <div class="info-item">
                                <strong>Region:</strong> %s
                            </div>
                            <div class="info-item">
                                <strong>Country:</strong> %s - %s
                            </div>
                        </div>
                    </div>

                    <!-- Activity Statistics -->
                    <div class="lookup-section activity-stats">
                        <h3>Activity Metrics</h3>
                        <div class="info-grid">
                            <div class="info-item">
                                <strong>Total messages:</strong> %d
                            </div>
                            <div class="info-item">
                                <strong>Conversations:</strong> %d
                            </div>
                            <div class="info-item">
                                <strong>Reports Sent:</strong> %d
                            </div>
                            <div class="info-item">
                                <strong>IP Usage Count:</strong> %d user%s
                            </div>
                            <div class="info-item">
                                <strong>Users with this IP:</strong>
                                %s
                            </div>
                        </div>
                    </div>

                    <!-- Report Statistics -->
                    <div class="lookup-section report-stats">
                        <h3>Report History</h3>
                        <div class="info-grid">
                            <div class="info-item">
                                <strong><span style="font-size: 1.2em; margin-right: 8px; vertical-align: middle;">⚠️</span>Spam Reports:</strong> %d
                            </div>
                            <div class="info-item">
                                <strong><span style="font-size: 1.2em; margin-right: 8px; vertical-align: middle;">🔪</span>Harassment:</strong> %d
                            </div>
                            <div class="info-item">
                                <strong><span style="font-size: 1.2em; margin-right: 8px; vertical-align: middle;">💣</span>Offensive:</strong> %d
                            </div>
                            <div class="info-item">
                                <strong><span style="font-size: 1.2em; margin-right: 8px; vertical-align: middle;">🔞</span>Inappropriate:</strong> %d
                            </div>
                            <div class="info-item">
                                <strong><span style="font-size: 1.2em; margin-right: 8px; vertical-align: middle;">❓</span>Other Reports:</strong> %d
                            </div>
                        </div>
                    </div>

                    <!-- Technical Details -->
                    <div class="lookup-section tech-details">
                        <h3>Technical Information</h3>
                        <div class="info-grid">
                            <div class="info-item">
                                <strong>Device Type:</strong> %s %s
                            </div>
                            <div class="info-item">
                                <strong>User Agent:</strong> 
                                <div class="user-agent-text">%s</div>
                            </div>
                        </div>
                    </div>

                    <!-- Toxicity Status -->
                    <div class="lookup-section toxicity-status" style="background-color: %s1A;">
                        <h3>Trust Score</h3>
                        <div class="info-grid">
                            <div class="info-item">
                                <strong>Status:</strong> %s %s
                            </div>
                            <div class="info-item">
                                <strong>Reliability:</strong> %s%%
                            </div>
                            <div class="info-item">
                                <strong>Details:</strong> %s
                            </div>
                        </div>
                    </div>

                    <!-- Action Buttons -->
                    <div class="lookup-section action-buttons">
                        <button type="button" class="button" onclick="jQuery(\'#ip-lookup-popup\').hide();">Close</button>
                        <a href="https://www.whatismyip.com/ip/%s/" target="_blank" class="button">ASN Lookup</a>
                        %s
                    </div>
                </div>
            </div>',
            esc_html($display_name),
            esc_html($ip),
            $record->extra && $record->extra->flag ? $record->extra->flag : '🏳️',
            $is_banned ? '<span class="banned-flag">🚫 BANNED</span>' : '',
            esc_html($record->city && $record->city->name ? $record->city->name : 'Unknown City'),
            esc_html($record->mostSpecificSubdivision && $record->mostSpecificSubdivision->name ? $record->mostSpecificSubdivision->name : 'Unknown Region'),
            esc_html($record->subdivisions && !empty($record->subdivisions[0]) && $record->subdivisions[0]->name ? $record->subdivisions[0]->name : 'Unknown State'),
            esc_html($record->country && $record->country->isoCode ? $record->country->isoCode : 'Unknown'),
            esc_html($record->registeredCountry && $record->registeredCountry->name ? $record->registeredCountry->name : 'Unknown Country'),
            $message_stats->total_messages,
            $message_stats->total_conversations,
            $reports_sent,
            count($ip_usage),
            count($ip_usage) > 1 ? 's' : '',
            !empty($ip_users_list) ? '<ul class="ip-users-list"><li>' . implode('</li><li>', $ip_users_list) . '</li></ul>' : 'None',
            $report_categories['spam'],
            $report_categories['harassment'],
            $report_categories['offensive'],
            $report_categories['inappropriate'],
            $report_categories['other'],
            $device_icon,
            esc_html(ucfirst($device_type)),
            esc_html($user_agent),
            esc_attr($toxicity_status['color']),
            esc_html($toxicity_status['level']),
            $toxicity_status['icon'],
            $toxicity_status['percentage'],
            esc_html($toxicity_status['details']),
            esc_attr($ip),
            $is_banned 
                ? '<button type="button" class="button button-disabled" disabled>IP Already Banned</button>'
                : sprintf('<button type="button" class="button button-primary" onclick="window.banIP(\'%s\')">Ban IP</button>', esc_attr($ip))
        );
        
        wp_send_json_success(['html' => $html]);
    } else {
        wp_send_json_error('Failed to lookup IP');
    }
}




/* --- Function bm_ban_ip_callback ---
   AJAX HANDLER FOR BANNING IPS
----------------------------------------------- */
add_action('wp_ajax_bm_ban_ip', 'bm_ban_ip_callback');
function bm_ban_ip_callback() {
    check_ajax_referer('bm_ban_ip', 'nonce');
    
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
    }

    $ip = sanitize_text_field($_POST['ip']);
    
    if (empty($ip)) {
        wp_send_json_error('Invalid IP address');
    }

    // Add debugging
    error_log('Attempting to ban IP: ' . $ip);

    // Get current banned IPs from WP-Ban
    $banned_ips = get_option('banned_ips', array());
    
    // Add debugging
    error_log('Current banned IPs: ' . print_r($banned_ips, true));
    
    // Check if IP is already banned
    if (in_array($ip, $banned_ips)) {
        wp_send_json_error('IP is already banned');
    }

    // Add new IP to banned list
    $banned_ips[] = $ip;
    
    // Update the banned IPs option
    $update_result = update_option('banned_ips', $banned_ips);

    // Add debugging
    error_log('Update result: ' . ($update_result ? 'success' : 'failed'));
    error_log('New banned IPs list: ' . print_r(get_option('banned_ips'), true));

    if ($update_result) {
        wp_send_json_success('IP has been banned successfully');
    } else {
        wp_send_json_error('Failed to ban IP');
    }
}


/* --- Handlers bm_delete_function and bm_delete_message ---
   AJAX HANDLERS FOR REPORT ABUSE DATAS
----------------------------------------------- */
add_action('wp_ajax_bm_delete_report', 'bm_delete_report_callback');
function bm_delete_report_callback() {
    check_ajax_referer('bm_report_actions', 'nonce');
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
    }

    global $wpdb;
    $message_id = intval($_POST['message_id']);
    $reporter_id = intval($_POST['reporter_id']);
    
    // Get the meta table name
    $meta_table = bm_get_table('meta');
    
    // Get existing reports
    $existing_reports = $wpdb->get_var($wpdb->prepare(
        "SELECT meta_value FROM {$meta_table} WHERE bm_message_id = %d AND meta_key = 'user_reports'",
        $message_id
    ));
    
    if (!$existing_reports) {
        wp_send_json_error('No reports found');
        return;
    }
    
    $reports = maybe_unserialize($existing_reports);
    if (!is_array($reports)) {
        wp_send_json_error('Invalid report data');
        return;
    }
    
    if (!isset($reports[$reporter_id])) {
        wp_send_json_error('Report not found');
        return;
    }
    
    // Remove the specific report
    unset($reports[$reporter_id]);
    
    if (empty($reports)) {
        // If no reports left, delete the meta entry
        $wpdb->delete(
            $meta_table,
            array(
                'bm_message_id' => $message_id,
                'meta_key' => 'user_reports'
            ),
            array('%d', '%s')
        );
    } else {
        // Update with remaining reports
        $wpdb->update(
            $meta_table,
            array('meta_value' => maybe_serialize($reports)),
            array(
                'bm_message_id' => $message_id,
                'meta_key' => 'user_reports'
            ),
            array('%s'),
            array('%d', '%s')
        );
    }
    
    // Clear cache
    wp_cache_delete($message_id, 'bm_message_meta');
    
    wp_send_json_success();
}


add_action('wp_ajax_bm_delete_message', 'bm_delete_message_callback');
function bm_delete_message_callback() {
    check_ajax_referer('bm_report_actions', 'nonce');
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
    }

    $message_id = intval($_POST['message_id']);
    
    global $wpdb;
    $result = $wpdb->delete(bm_get_table('messages'), ['id' => $message_id]);
    
    if ($result !== false) {
        wp_send_json_success();
    }
    wp_send_json_error('Failed to delete message');
}




/* --- Function update_report_status ---
   HANDLE REPORT STATUS UPDATES
----------------------------------------------- */
add_action('wp_ajax_bm_update_report_status', 'bm_update_report_status_callback');
function bm_update_report_status_callback() {
    check_ajax_referer('bm_report_actions', 'nonce');
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
    }

    $message_id = intval($_POST['message_id']);
    $reporter_id = intval($_POST['reporter_id']);
    $new_status = sanitize_text_field($_POST['status']);

    $valid_statuses = array('new', 'dismissed', 'resolved', 'monitoring', 'user_banned');
    if (!in_array($new_status, $valid_statuses)) {
        wp_send_json_error('Invalid status');
    }

    global $wpdb;
    $meta_table = bm_get_table('meta');
    
    // Get existing reports
    $existing_reports = $wpdb->get_var($wpdb->prepare(
        "SELECT meta_value FROM {$meta_table} 
        WHERE bm_message_id = %d AND meta_key = 'user_reports'",
        $message_id
    ));
    
    if (!$existing_reports) {
        wp_send_json_error('No reports found');
        return;
    }
    
    $reports = maybe_unserialize($existing_reports);
    if (!isset($reports[$reporter_id])) {
        wp_send_json_error('Report not found');
        return;
    }
    
    // Update the status
    $reports[$reporter_id]['status'] = $new_status;
    $reports[$reporter_id]['status_updated'] = current_time('mysql');
    $reports[$reporter_id]['status_updated_by'] = get_current_user_id();
    
    // Save updated reports
    $result = $wpdb->update(
        $meta_table,
        array('meta_value' => maybe_serialize($reports)),
        array(
            'bm_message_id' => $message_id,
            'meta_key' => 'user_reports'
        ),
        array('%s'),
        array('%d', '%s')
    );

    if ($result !== false) {
        wp_cache_delete($message_id, 'bm_message_meta');
        wp_send_json_success();
    }
    wp_send_json_error('Failed to update status');
}





/* --- Function bm_add_ban_scripts ---
   ADD JAVASCRIPT FOR BAN FUNCTIONALITY
----------------------------------------------- */
add_action('admin_footer', 'bm_add_ban_scripts');
function bm_add_ban_scripts() {
    $screen = get_current_screen();
	if ($screen->id !== 'toplevel_page_admin-sync-users') {
        return;
    }
    ?>
	<script type="text/javascript">
	// Add this at the top of your script to define the nonce
	var bm_nonce = '<?php echo wp_create_nonce("bm_lookup_ip"); ?>';

	jQuery(document).ready(function($) {
		// Use event delegation for the IP lookup click handler
		$(document).on('click', '.lookup-ip', function(e) {
			e.preventDefault();
			var link = $(this);
			var ip = link.data('ip');
			var userRow = link.closest('tr');
			var userId = userRow.find('td:first').text().trim();
			
			console.log('Looking up IP:', ip); // Debug log
			link.css('opacity', '0.5');
			
			$.post(ajaxurl, {
				action: 'bm_lookup_ip',
				ip: ip,
				display_name: userRow.find('td:eq(1)').text(),
				user_id: userId,
				nonce: bm_nonce
			}, function(response) {
				console.log('Response received:', response); // Debug log
				link.css('opacity', '1');
				
				if (response.success) {
					$('#ip-lookup-content').html(response.data.html);
					$('#ip-lookup-popup').show();
				} else {
					alert('Failed to lookup IP: ' + (response.data || 'Unknown error'));
				}
			}).fail(function(xhr, status, error) {
				console.error('AJAX Error:', error);
				link.css('opacity', '1');
				alert('Failed to lookup IP: ' + error);
			});
		});

		// Add a close button handler
		$(document).on('click', '.popup-close-btn', function() {
			$('#ip-lookup-popup').hide();
		});

		// Close popup when clicking outside
		$(document).on('click', function(e) {
			if ($(e.target).is('#ip-lookup-popup')) {
				$('#ip-lookup-popup').hide();
			}
		});
	});
	</script>
	
	<style>
	/* Add these styles to ensure the popup is visible */
	#ip-lookup-popup {
		position: fixed;
		left: 50%;
		top: 50%;
		transform: translate(-50%, -50%);
		background: #fff;
		padding: 20px;
		border: 1px solid #ccc;
		box-shadow: 0 0 10px rgba(0,0,0,0.5);
		z-index: 9999;
		max-height: 90vh;
		overflow-y: auto;
		display: none;
	}

	.popup-close-btn {
		position: absolute;
		top: 10px;
		right: 10px;
		font-size: 24px;
		cursor: pointer;
		background: none;
		border: none;
		padding: 5px;
	}
	
	.ip-users-list {
    margin: 5px 0 0 20px;
    padding: 0;
    list-style: none;
}

	.ip-users-list li {
		margin-bottom: 3px;
		font-size: 0.9em;
		color: #666;
	}

	.ip-users-list li:before {
		content: "•";
		color: #999;
		display: inline-block;
		width: 1em;
		margin-left: -1em;
	}
	
	.reports-summary {
		background: white;
		border-radius: 8px;
		box-shadow: 0 2px 10px rgba(0,0,0,0.1);
		margin-bottom: 20px;
	}

	.reports-header {
		border-bottom: 2px solid #eee;
		padding: 15px;
	}

	.header-content {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 10px;
	}

	.header-icon {
		color: #2196F3;
	}

	.reports-header h3 {
		margin: 0;
		font-size: 1.5em;
		color: #333;
	}

	.stats-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 15px;
		padding: 15px;
	}

	.stat-card {
		background: #f8f9fa;
		border-radius: 8px;
		padding: 15px;
		border: 1px solid #e9ecef;
	}

	.stat-content {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 10px;
	}

	.stat-icon {
		font-size: 1.2em;
	}

	.stat-label {
		flex-grow: 1;
		color: #495057;
		font-weight: 500;
	}

	.stat-value {
		font-size: 1.2em;
		font-weight: bold;
		color: #2196F3;
	}

	.report-entry {
		background: #f8f9fa;
		border-radius: 8px;
		padding: 20px;
		margin-bottom: 20px;
		border: 1px solid #e9ecef;
	}

	.report-timestamp {
		margin-bottom: 15px;
	}

	.timestamp-content {
		display: flex;
		align-items: center;
		gap: 8px;
		background: #fff3cd;
		padding: 8px 12px;
		border-radius: 6px;
		display: inline-flex;
	}

	.calendar-icon {
		color: #856404;
	}

	.users-info {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 15px;
		margin-bottom: 15px;
	}

	.reporter, .reported {
		padding: 15px;
		border-radius: 6px;
	}

	.reporter {
		background: #d4edda;
	}

	.reported {
		background: #f8d7da;
	}

	.user-header {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 8px;
	}

	.user-header h4 {
		margin: 0;
		color: #333;
	}

	.report-details {
		background: #cce5ff;
		padding: 15px;
		border-radius: 6px;
		margin-bottom: 15px;
	}

	.details-header {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 8px;
	}

	.details-content {
		background: white;
		padding: 10px;
		border-radius: 4px;
		border: 1px solid #b8daff;
	}

	.status-badge {
		padding: 4px 8px;
		border-radius: 12px;
		color: white;
		font-size: 0.9em;
		margin: 0 8px;
	}

	.action-buttons {
		display: flex;
		gap: 10px;
		justify-content: flex-end;
		margin-top: 15px;
	}

	.button {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 16px;
		border-radius: 4px;
		border: none;
		cursor: pointer;
		font-weight: 500;
		transition: all 0.2s;
	}

	.delete-report {
		background: #e9ecef;
		color: #495057;
	}

	.delete-report:hover {
		background: #dee2e6;
	}

	.ban-ip {
		background: #dc3545;
		color: white;
	}

	.ban-ip:hover {
		background: #c82333;
	}

	.status-update {
		padding: 4px 8px;
		border-radius: 4px;
		border: 1px solid #ced4da;
		margin-left: 8px;
	}
	</style>

    <?php
}


/* --- Function get_guest_display_name ---
   GET DISPLAY NAME FOR GUEST USERS
----------------------------------------------- */
function get_guest_display_name($user_id) {
    // If it's not a negative ID (not a guest), return null
    if ($user_id >= 0) return null;
    
    global $wpdb;
    $guest_id = abs($user_id);
    
    // Get the name from guests table (changed from display_name to name)
    $guest_name = $wpdb->get_var($wpdb->prepare(
        "SELECT name FROM " . bm_get_table('guests') . " WHERE id = %d",
        $guest_id
    ));
    
    return $guest_name ?: 'Unknown User';
}

/* --- Function parse_reports_data ---
   PARSE AND FORMAT REPORT DATA
----------------------------------------------- */
function parse_reports_data($reports_string) {
    if (empty($reports_string)) {
        return array(); // Return empty array instead of null
    }
    
    $processed_messages = array(); // Initialize the array
    $seen_messages = array(); // Track unique message IDs
    $entries = explode('||', $reports_string);

    foreach ($entries as $entry) {
        if (empty($entry)) continue;
        
        $parts = explode(':', $entry, 3);
        if (count($parts) < 3) continue;
        
        list($msg_id, $message, $report_data) = $parts;
        
        // Skip if we've already processed this message
        if (isset($seen_messages[$msg_id])) {
            continue;
        }
        
        if (empty($report_data)) continue;
        
        $report_array = maybe_unserialize($report_data);
        if (!is_array($report_array)) {
            error_log('Failed to unserialize report data for message ID: ' . $msg_id);
            continue;
        }

        $seen_messages[$msg_id] = true; // Mark this message as processed

        $processed_messages[$msg_id] = array(
            'message_id' => intval($msg_id),
            'content' => wp_kses($message, array()),
            'reporters' => array()
        );

        foreach ($report_array as $reporter_id => $report_info) {
            // Initialize reporter name
            $reporter_name = '';
            $found_user = false;

            // For WordPress users (positive IDs)
            if ($reporter_id > 0) {
                // Try to get user from database directly
                global $wpdb;
                $reporter_data = $wpdb->get_row($wpdb->prepare(
                    "SELECT ID, display_name FROM {$wpdb->users} WHERE ID = %d",
                    $reporter_id
                ));
                
                if ($reporter_data) {
                    $reporter_name = $reporter_data->display_name;
                    $found_user = true;
                } elseif (function_exists('bp_core_get_user_displayname')) {
                    $bp_display_name = bp_core_get_user_displayname($reporter_id);
                    if (!empty($bp_display_name)) {
                        $reporter_name = $bp_display_name;
                        $found_user = true;
                    }
                }

                if (!$found_user) {
                    $user = get_user_by('ID', $reporter_id);
                    if ($user) {
                        $reporter_name = $user->display_name;
                        $found_user = true;
                    }
                }
            } 
            // For guest users (negative IDs)
            else {
                $reporter_name = get_guest_display_name($reporter_id);
                $found_user = !empty($reporter_name);
            }

            if (!$found_user) {
                $reporter_name = 'Unknown User';
            }

            // Clean and format the time
            $report_time = isset($report_info['time']) ? $report_info['time'] : '';
            if (!empty($report_time)) {
                $report_time = wp_date(
                    get_option('date_format') . ' ' . get_option('time_format'),
                    strtotime($report_time)
                );
            }

            // Clean and prepare the description
            $description = isset($report_info['description']) ? $report_info['description'] : '';
            $description = wp_kses($description, array());
            $description = !empty($description) ? $description : '(No description provided)';

            // Add status information
            $status = isset($report_info['status']) ? $report_info['status'] : 'new';

            $processed_messages[$msg_id]['reporters'][] = array(
                'reporter_id' => $reporter_id,
                'reporter_name' => $reporter_name,
                'category' => isset($report_info['category']) ? 
                    wp_kses($report_info['category'], array()) : 'Unknown Category',
                'description' => $description,
                'time' => $report_time,
                'status' => $status
            );
        }
    }
    
    return array_values($processed_messages); // Return empty array if no messages processed
}


/* --- Function sync_users_page ---
   DISPLAY AND HANDLE SYNC USERS PAGE
----------------------------------------------- */

function sync_users_page() {
    // Handle sync users action
    if (isset($_POST['sync_users'])) {
        Better_Messages_Users()->sync_all_users();
        echo '<div class="updated"><p>Users synced successfully!</p></div>';
    }

    // Handle flush reports action
    if (isset($_POST['flush_reports'])) {
        if (check_admin_referer('flush_all_reports', 'flush_reports_nonce')) {
            $deleted = flush_all_reports();
            if ($deleted !== false) {
                echo '<div class="updated"><p>' . sprintf('Successfully deleted reports from %d messages!', $deleted) . '</p></div>';
            } else {
                echo '<div class="error"><p>Error occurred while deleting reports.</p></div>';
            }
        }
    }

    // Get active tab
    $active_tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'users';
    ?>
    <div class="wrap">
        <h1>Admin Sync Users</h1>

        <h2 class="nav-tab-wrapper">
            <a href="?page=admin-sync-users&tab=users" 
               class="nav-tab <?php echo $active_tab === 'users' ? 'nav-tab-active' : ''; ?>">
                Users List
            </a>
            <a href="?page=admin-sync-users&tab=reports" 
               class="nav-tab <?php echo $active_tab === 'reports' ? 'nav-tab-active' : ''; ?>">
                Reports List
            </a>
        </h2>

        <div class="admin-actions" style="display: flex; gap: 10px; margin-bottom: 20px;">
            <form method="post" action="">
                <input type="submit" name="sync_users" value="Sync All Users" class="button-primary" />
            </form>

            <button id="show-stats" class="button-secondary" style="margin-left: auto;">Reports Statistics</button>

            <form method="post" action="">
                <?php 
                wp_nonce_field('flush_all_reports', 'flush_reports_nonce');
                $total_reports = get_total_reports_count();
                ?>
                <input type="submit" 
                       name="flush_reports" 
                       value="Flush All Reports (<?php echo $total_reports; ?>)" 
                       class="button-secondary" 
                       onclick="return confirm('Are you sure you want to delete ALL reports? This action cannot be undone.');"
                       <?php echo $total_reports === 0 ? 'disabled' : ''; ?> />
            </form>
        </div>

        <?php
		if ($active_tab === 'reports') {
		// Reports Table
		global $wpdb;
		$meta_table = bm_get_table('meta');
		$messages_table = bm_get_table('messages');
		$users_table = bm_get_table('users');

		$reports = $wpdb->get_results("
			SELECT 
				msg.sender_id as reported_id,
				u_reported.display_name as reported_name,
				u_reported.ip as reported_ip,
				meta.meta_value as report_data,
				msg.message as message_content,
				meta.bm_message_id as message_id,
				msg.date_sent as report_date,
				reporter.ip as reporter_ip  -- Add reporter IP
			FROM {$meta_table} meta
			JOIN {$messages_table} msg ON meta.bm_message_id = msg.id
			JOIN {$users_table} u_reported ON msg.sender_id = u_reported.ID
			LEFT JOIN {$users_table} reporter ON reporter.ID = SUBSTRING_INDEX(SUBSTRING_INDEX(meta.meta_value, 'i:', -1), ';', 1)
			WHERE meta.meta_key = 'user_reports'
			ORDER BY msg.date_sent DESC
		");
		?>
		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<th>ID Signalé</th>
					<th>Nom Signalé</th>
					<th>Toxicity Reported</th>
					<th>Date du Rapport</th>
					<th>Raison</th>
					<th>Description</th>
					<th>ID Reporter</th>
					<th>Nom Reporter</th>
					<th>Toxicity Reporter</th>
					<th>Actions</th>
					<th>Report Status</th>
				</tr>
			</thead>
			<tbody>
			<?php
				$processed_messages = [];

			foreach ($reports as $report) {
				$report_data = maybe_unserialize($report->report_data);
				if (!is_array($report_data)) continue;

				foreach ($report_data as $reporter_id => $report_info) {
					echo '<tr>';
					
					// Reported User
					echo '<td>' . esc_html($report->reported_id) . '</td>';
					echo '<td><a href="#" class="user-details-link" data-user-id="' . 
						 esc_attr($report->reported_id) . '" data-user-name="' . 
						 esc_attr($report->reported_name) . '" data-user-ip="' . 
						 esc_attr($report->reported_ip) . '">' . 
						 esc_html($report->reported_name) . '</a></td>';
					
					// Toxicity Status
					$toxicity_status = Better_Messages_User_Toxicity()->get_toxicity_status($report->reported_id);
					echo '<td>';
					echo '<div style="background-color: ' . esc_attr($toxicity_status['color']) . '1A; padding: 5px; border-radius: 4px;">';
					echo $toxicity_status['icon'] . ' ';
					echo '<strong>' . esc_html($toxicity_status['level']) . '</strong><br>';
					echo 'Reliability: ' . $toxicity_status['percentage'] . '%';
					echo '</div>';
					echo '</td>';
					
					// Report Date
					echo '<td>' . wp_date('d/m/Y H:i', strtotime($report_info['time'])) . '</td>';
					
					// Category
					$category_icons = [
						'spam' => '⚠️',
						'harassment' => '🔪',
						'offensive' => '💣',
						'inappropriate' => '🔞',
						'other' => '❓'
					];
					echo '<td>';
					$icon = isset($category_icons[strtolower($report_info['category'])]) ? $category_icons[strtolower($report_info['category'])] : '';
					echo $icon . esc_html($report_info['category']);
					echo '</td>';
					
					// Description
					echo '<td>' . esc_html($report_info['description']) . '</td>';
					
					// Reporter Info
					echo '<td>' . esc_html($reporter_id) . '</td>';
					
					// Get Reporter Name
					$reporter_name = '';
					$reporter_toxicity = null;
					if ($reporter_id > 0) {
						$reporter_name = $wpdb->get_var($wpdb->prepare(
							"SELECT display_name FROM {$users_table} WHERE ID = %d",
							$reporter_id
						));
						$reporter_toxicity = Better_Messages_User_Toxicity()->get_toxicity_status($reporter_id);
					} else {
						$guest_id = abs($reporter_id);
						$reporter_name = $wpdb->get_var($wpdb->prepare(
							"SELECT name FROM " . bm_get_table('guests') . " WHERE id = %d",
							$guest_id
						));
						$reporter_toxicity = Better_Messages_User_Toxicity()->get_toxicity_status($reporter_id);
					}
					
					// Reporter Name column
					echo '<td><a href="#" class="user-details-link" data-user-id="' . 
						esc_attr($reporter_id) . '" data-user-name="' . 
						esc_attr($reporter_name) . '" data-user-ip="' . 
						esc_attr($report->reporter_ip) . '">' . 
						esc_html($reporter_name) . '</a></td>';
					
					// Reporter Toxicity
					echo '<td>';
					if ($reporter_toxicity) {
						echo '<div style="background-color: ' . esc_attr($reporter_toxicity['color']) . '1A; padding: 5px; border-radius: 4px;">';
						echo $reporter_toxicity['icon'] . ' ';
						echo '<strong>' . esc_html($reporter_toxicity['level']) . '</strong><br>';
						echo 'Reliability: ' . $reporter_toxicity['percentage'] . '%';
						echo '</div>';
					}
					echo '</td>';
					
					// Actions
					echo '<td>';
					echo '<div class="action-icons">';
					echo '<span class="dashicons dashicons-trash action-icon" onclick="deleteReport(' . $report->message_id . ', ' . $reporter_id . ')" title="Delete Report"></span>';
					echo '<span class="dashicons dashicons-no-alt action-icon" onclick="deleteMessage(' . $report->message_id . ')" title="Delete Message"></span>';
					echo '<span class="dashicons dashicons-dismiss action-icon" onclick="banIP(\'' . esc_attr($report->reported_ip) . '\')" title="Ban IP"></span>';
					echo '</div>';
					echo '</td>';
					
					// Status
					echo '<td>';
					$status = isset($report_info['status']) ? $report_info['status'] : 'new';
					$statusConfig = [
						'new' => ['color' => '#4CAF50', 'icon' => ''],
						'resolved' => ['color' => '#2196F3', 'icon' => '✔️'],
						'dismissed' => ['color' => '#f44336', 'icon' => '❌'],
						'monitoring' => ['color' => '#ffc107', 'icon' => '⚠️'],
						'user_banned' => ['color' => '#000000', 'icon' => '🚫']
					];
					
					echo '<div class="status-container">';
					echo '<span class="current-status" style="background-color: ' . esc_attr($statusConfig[$status]['color']) . ';">' . 
						 $statusConfig[$status]['icon'] . ' ' . strtoupper($status) . '</span>';
					echo '<div class="status-options">';
					foreach ($statusConfig as $statusKey => $config) {
						echo '<span class="status-option" onclick="updateReportStatus(' . $report->message_id . ', ' . $reporter_id . ', \'' . $statusKey . '\')" ' .
							 'style="background-color: ' . esc_attr($config['color']) . ';">' . 
							 $config['icon'] . ' ' . strtoupper($statusKey) . '</span>';
					}
					echo '</div>';
					echo '</div>';
					echo '</td>';
					
					echo '</tr>';
				}
			}
			?>
			</tbody>
		</table>

		<style>
		.action-icons {
			display: flex;
			gap: 10px;
			justify-content: center;
		}

		.action-icon {
			cursor: pointer;
			color: #666;
			transition: color 0.2s;
		}

		.action-icon:hover {
			color: #dc3545;
		}

		/* Add icons specific styles */
		.dashicons-trash:hover { color: #dc3545; }
		.dashicons-no-alt:hover { color: #f44336; }
		.dashicons-dismiss:hover { color: #d32f2f; }
		
		.status-container {
    position: relative;
    display: inline-block;
}

		/* Status of Reports */
		.current-status {
			display: inline-flex;
			align-items: center;
			padding: 5px 10px;
			border-radius: 12px;
			color: white;
			cursor: pointer;
			gap: 5px;
		}

		.status-options {
			display: none;
			position: absolute;
			top: 100%;
			left: 0;
			background: white;
			border: 1px solid #ddd;
			border-radius: 4px;
			box-shadow: 0 2px 5px rgba(0,0,0,0.2);
			z-index: 1000;
		}

		.status-option {
			display: flex;
			align-items: center;
			padding: 8px 12px;
			color: white;
			cursor: pointer;
			gap: 5px;
			white-space: nowrap;
		}

		.status-container:hover .status-options {
			display: block;
		}
		</style>
			
			
            <?php
        } else {
            // Users Table (Your existing code)
            global $wpdb;
            $users_table = bm_get_table('users');
            $moderation_table = bm_get_table('moderation');
            $guests_table = bm_get_table('guests');
            $messages_table = bm_get_table('messages');
            $wp_users_table = $wpdb->users;
            $recipients_table = bm_get_table('recipients');
            
            $sql = "
                SELECT 
                    u.*,
                    COALESCE(u.ip, g.ip) as user_ip,
                    COALESCE(u.user_agent, g.user_agent) as user_agent,
                    COALESCE(g.created_at, wu.user_registered) as registered_at,
                    MAX(CASE WHEN m.type = 'ban' AND m.expiration > NOW() THEN 1 ELSE 0 END) as is_banned,
                    MAX(CASE WHEN m.type = 'mute' AND m.expiration > NOW() THEN 1 ELSE 0 END) as is_muted,
                    MAX(CASE WHEN m.type = 'ban' THEN m.expiration ELSE NULL END) as ban_expiration,
                    MAX(CASE WHEN m.type = 'mute' THEN m.expiration ELSE NULL END) as mute_expiration,
                    COUNT(DISTINCT msg.id) as message_count,
                    COUNT(DISTINCT r.thread_id) as conversation_count,
                    u.age,
                    u.departement,
                    u.ville,
                    u.sexe,
                    GROUP_CONCAT(DISTINCT 
                        CASE 
                            WHEN msg_meta.meta_key = 'user_reports' 
                            THEN CONCAT(msg.id, ':', msg.message, ':', msg_meta.meta_value)
                        END
                        SEPARATOR '||'
                    ) as reports_data
                FROM {$users_table} u
                LEFT JOIN {$moderation_table} m ON u.ID = m.user_id
                LEFT JOIN {$guests_table} g ON ABS(u.ID) = g.id
                LEFT JOIN {$wp_users_table} wu ON u.ID = wu.ID
                LEFT JOIN {$messages_table} msg ON u.ID = msg.sender_id
                LEFT JOIN {$recipients_table} r ON u.ID = r.user_id
                LEFT JOIN " . bm_get_table('meta') . " msg_meta ON msg.id = msg_meta.bm_message_id 
                    AND msg_meta.meta_key = 'user_reports'
                GROUP BY u.ID
                ORDER BY u.last_activity DESC";

            $users = $wpdb->get_results($sql);
            ?>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Display Name</th>
                        <th>Age</th>
                        <th>Département</th>
                        <th>Ville</th>
                        <th>Sexe</th>
                        <th>Messages</th>
                        <th>Conversations</th>
                        <th>Registered At</th>
                        <th>IP</th>
                        <th>User Agent</th>
                        <th>Status</th>
                        <th>Reports</th>
                    </tr>
                </thead>
                <tbody>
                <?php
                foreach ($users as $user_data) {
                    echo '<tr>';
                    echo '<td>' . esc_html($user_data->ID) . '</td>';
                    echo '<td>' . esc_html($user_data->display_name) . '</td>';
                    echo '<td>' . esc_html($user_data->age) . '</td>';
                    echo '<td>' . esc_html($user_data->departement) . '</td>';
                    echo '<td>' . esc_html($user_data->ville) . '</td>';
                    echo '<td>' . esc_html($user_data->sexe) . '</td>';
                    echo '<td style="text-align: center;">' . esc_html($user_data->message_count) . '</td>';
                    echo '<td style="text-align: center;">' . esc_html($user_data->conversation_count) . '</td>';
                    
                    // Registration date formatting
                    echo '<td>';
                    if (!empty($user_data->registered_at)) {
                        $registered_time = strtotime($user_data->registered_at);
                        $now = current_time('timestamp');
                        $diff = $now - $registered_time;
                        
                        $minutes = floor($diff / 60);
                        $hours = floor($minutes / 60);
                        $days = floor($hours / 24);
                        
                        $remaining_hours = $hours % 24;
                        $remaining_minutes = $minutes % 60;
                        
                        if ($days > 0) {
                            echo $days . ' day' . ($days > 1 ? 's' : '') . ', ';
                        }
                        if ($remaining_hours > 0 || $days > 0) {
                            echo $remaining_hours . ' hour' . ($remaining_hours > 1 ? 's' : '') . ', ';
                        }
                        echo $remaining_minutes . ' minute' . ($remaining_minutes > 1 ? 's' : '');
                    }
                    echo '</td>';
                    
                    // IP column
                    echo '<td>';
                    if (!empty($user_data->user_ip)) {
                        $record = geoip_detect2_get_info_from_ip($user_data->user_ip);
                        $flag = $record && $record->extra && $record->extra->flag ? $record->extra->flag : '🏳️';
                        echo sprintf(
                            '<a href="#" class="lookup-ip" data-ip="%s">%s</a> %s',
                            esc_attr($user_data->user_ip),
                            esc_html($user_data->user_ip),
                            $flag
                        );
                    }
                    echo '</td>';
                    
                    // User Agent column
                    echo '<td>';
                    if (!empty($user_data->user_agent)) {
                        $user_agent = (string) $user_data->user_agent;
                        $device_type = get_device_type($user_agent);
                        $icon = $device_type === 'mobile' ? '📱' : '💻';
                        echo '<span title="' . esc_attr($user_agent) . '">';
                        echo $icon . ' ' . esc_html(strlen($user_agent) > 50 ? substr($user_agent, 0, 47) . '...' : $user_agent);
                        echo '</span>';
                    } else {
                        echo '–';
                    }
                    echo '</td>';
                    
                    // Status column
                    echo '<td>';
                    $banned_ips = get_option('banned_ips', array());
                    $is_ip_banned = !empty($user_data->user_ip) && in_array($user_data->user_ip, $banned_ips);

                    if ($is_ip_banned) {
                        echo '<span class="bm-status ip-banned" title="IP Permanently Banned">⛔</span>';
                    } 
                    if ($user_data->is_banned) {
                        echo '<span class="bm-status banned" title="Temporarily Banned until ' . 
                            esc_attr(wp_date(get_option('date_format') . ' ' . get_option('time_format'), 
                            strtotime($user_data->ban_expiration))) . '">🚫</span>';
                    } 
                    if ($user_data->is_muted) {
                        echo '<span class="bm-status muted" title="Muted until ' . 
                            esc_attr(wp_date(get_option('date_format') . ' ' . get_option('time_format'), 
                            strtotime($user_data->mute_expiration))) . '">🔇</span>';
                    }

                    $toxicity_instance = Better_Messages_User_Toxicity();
                    if ($toxicity_instance && method_exists($toxicity_instance, 'get_toxicity_status')) {
                        try {
                            $toxicity_status = $toxicity_instance->get_toxicity_status($user_data->ID);
                            echo '<div style="margin-top: 5px; padding: 5px; border-radius: 4px; background-color: ' . esc_attr($toxicity_status['color']) . '1A;">';
                            echo '<span title="' . esc_attr($toxicity_status['details']) . '" style="color: ' . esc_attr($toxicity_status['color']) . ';">';
                            echo $toxicity_status['icon'] . ' ';
                            echo '<strong>' . esc_html($toxicity_status['level']) . '</strong><br>';
                            echo 'Reliability: ' . $toxicity_status['percentage'] . '%';
                            echo '</span>';
                            echo '</div>';
                        } catch (Exception $e) {
                            error_log('Error getting toxicity status: ' . $e->getMessage());
                        }
                    }
                    echo '</td>';
                    
					// the Reports column section with proper escaping
					echo '<td>';
					if (!empty($user_data->reports_data)) {
						$reports = parse_reports_data($user_data->reports_data);
						$total_reports = 0;
						foreach ($reports as $report) {
							$total_reports += count($report['reporters']);
						}
						
						echo '<span class="bm-status reported" 
							  style="background: transparent;" 
							  data-reports=\'' . esc_attr(json_encode($reports)) . '\'
							  onclick="showReportPopup(this)"
							  title="Has ' . $total_reports . ' reports">📋 ' . $total_reports . '</span>';
					}
					echo '</td>';
                    
                    echo '</tr>';
                }
                ?>
                </tbody>
            </table>
            <?php
        }
        ?>

        <!-- Popup Container -->
        <div id="ip-lookup-popup" style="display:none; position:fixed; left:50%; top:50%; 
             transform:translate(-50%, -50%); background:#fff; padding:20px; border:1px solid #ccc; 
             box-shadow:0 0 10px rgba(0,0,0,0.5); z-index:9999; max-height:90vh; overflow-y:auto;">
            <div id="ip-lookup-content"></div>
        </div>


        <!-- Add necessary JavaScript -->
		<script type="text/javascript">
		
		window.showReportPopup = function(element) {
			const reports = JSON.parse(element.dataset.reports);
			const userRow = element.closest('tr');
			const reportedUser = {
				id: userRow.cells[0].textContent.trim(),
				name: userRow.cells[1].textContent.trim(),
				ip: userRow.cells[9].textContent.trim()
			};

			let content = '<div class="reports-popup">';
			content += '<button class="popup-close-btn" onclick="jQuery(\'#ip-lookup-popup\').hide();">×</button>';
			content += buildReportSummary(reports);
			content += buildReportDetails(reports, reportedUser);
			content += '</div>';
			
			jQuery('#ip-lookup-content').html(content);
			jQuery('#ip-lookup-popup').show();
		};
		
		jQuery(document).ready(function($) {
			// Handler for reports tab user details
			$('.user-details-link').click(function(e) {
				e.preventDefault();
				var userId = $(this).data('user-id');
				var userName = $(this).data('user-name');
				var userIp = $(this).data('user-ip');
				
				$.post(ajaxurl, {
					action: 'bm_lookup_ip',
					user_id: userId,
					display_name: userName,
					ip: userIp,
					nonce: bm_nonce
				}, function(response) {
					if (response.success) {
						$('#ip-lookup-content').html(response.data.html);
						$('#ip-lookup-popup').show();
					} else {
						alert('Failed to load user details: ' + response.data);
					}
				});
			});
		});
		</script>
    </div>
   



        
<style>
    /* Base styles */
    .ip-lookup-results { 
        min-width: 300px; 
        max-width: 500px; 
    }
    .ip-lookup-results p { 
        margin: 5px 0; 
    }
    .lookup-ip { 
        cursor: pointer; 
        text-decoration: underline; 
    }

    /* Status indicators */
    .bm-status { 
        display: inline-block; 
        margin: 0 3px; 
        font-size: 16px; 
    }
    .bm-status.banned { color: #f44336; }
    .bm-status.muted { color: #ff9800; }
    .bm-status.ip-banned { color: #d32f2f; }
    .bm-status.ok { color: #43a047; }
    .bm-status.reported { 
        cursor: pointer; 
        color: #ff4444; 
    }

    /* Table styles */
    .wp-list-table td { 
        vertical-align: middle; 
    }
    
    /* Button styles */
    .button-small {
        font-size: 11px !important;
        padding: 0 8px !important;
        line-height: 22px !important;
        height: 24px !important;
    }
    
    /* Popup styles */
    .reports-popup {
        max-width: 1100px !important;
        width: 90vw;
        max-height: 80vh;
        overflow-y: auto;
        padding: 20px;
        background: #fff;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }

    /* Stats specific styles */
    .stats-popup {
        max-width: 1100px !important;
        width: 90vw;
    }
    .stats-section {
        margin-bottom: 30px;
    }
    .stats-section h3 {
        margin-bottom: 15px;
    }
    .stats-section table {
        width: 100%;
    }

	/* Category icon styles */
	.stats-section table td {
		vertical-align: middle;
		padding: 8px;
		line-height: 1.4;
	}

	.stats-section table td span {
		display: inline-flex;
		align-items: center;
		vertical-align: middle;
	}

    /* Report entry styles */
	.report-entry {
		border: 1px solid #ccc;
		padding: 15px;
		margin-bottom: 15px;
		border-radius: 4px;
		display: flex;
		flex-direction: column;
		gap: 10px; /* Reduced from 15px */
	}

    /* Style for timestamp */
	.report-timestamp {
		font-weight: bold;
		color: #666;
		border-bottom: 1px solid #eee;
		padding-bottom: 8px;
		margin-bottom: 8px;
	}

	/* Description styles - new background color */
	.report-details {
		background-color: #fff2f2;
		padding: 10px;
		border-radius: 4px;
		margin: 5px 0;
	}

    /* User info styles */
    .message-info {
        background: #f5f5f5;
        padding: 10px;
        margin-bottom: 10px;
    }
	
	.users-info {
		display: flex; /* Changed from grid to flex */
		gap: 20px;
		margin: 10px 0;
	}
	
	.reporter, .reported {
		flex: 1;
		background: #fff;
		padding: 10px;
		border-radius: 4px;
	}
	
	.reporter h4, .reported h4 {
    display: inline-block;
    margin: 0;
    margin-right: 5px;
	}
    
    /* Category styles */
    .report-category {
        margin-top: 10px;
        padding-top: 10px;
        border-top: 1px solid #eee;
    }

    /* Action buttons and controls */
    .action-buttons {
        display: flex;
        gap: 10px;
        margin-top: 15px;
    }
    .admin-actions {
        display: flex;
        gap: 10px;
        margin-bottom: 20px;
        align-items: flex-start;
    }
    .admin-actions .button-secondary[disabled] {
        cursor: not-allowed;
        opacity: 0.6;
    }
    .admin-actions form {
        margin: 0;
    }

    /* Close button */
    .popup-close {
        position: absolute;
        top: 10px;
        right: 10px;
        cursor: pointer;
        font-size: 20px;
        color: #666;
    }
    .popup-close:hover {
        color: #000;
    }
	/* Close button styles */
	.popup-close-btn {
		position: absolute;
		top: 10px;
		right: 10px;
		background: none;
		border: none;
		font-size: 24px;
		color: #666;
		cursor: pointer;
		padding: 5px;
		line-height: 1;
	}

	.popup-close-btn:hover {
		color: #000;
	}
	
	/* Gender-based colors for admin table */
	.wp-list-table td:nth-child(6) {
		font-weight: bold;
	}

	.wp-list-table td:nth-child(6):contains('Homme') {
		color: #0093ff;
	}

	.wp-list-table td:nth-child(6):contains('Femme') {
		color: #ED0058;
	}

	.wp-list-table td:nth-child(6):contains('Trans/Trav') {
		color: #A107ED;
	}
	
		/* Toxicity status styles */
	.toxicity-status {
		margin-top: 5px;
		padding: 5px;
		border-radius: 4px;
		font-size: 0.9em;
		line-height: 1.3;
	}

	.toxicity-status strong {
		font-size: 1.1em;
	}

	.wp-list-table td {
		vertical-align: top !important;
	}
</style>

<script type="text/javascript">
jQuery(document).ready(function($) {
	// IP Lookup handler : Update the click handler to include user_id
	$('.lookup-ip').click(function(e) {
		e.preventDefault();
		var link = $(this);
		var ip = link.data('ip');
		var userRow = link.closest('tr');
		var userId = userRow.find('td:first').text().trim();
		
		link.css('opacity', '0.5');
		
		$.post(ajaxurl, {
			action: 'bm_lookup_ip',
			ip: ip,
			display_name: userRow.find('td:eq(1)').text(),
			user_id: userId,
			nonce: bm_nonce
		}, function(response) {
			link.css('opacity', '1');
			
			if (response.success) {
				$('#ip-lookup-content').html(response.data.html);
				$('#ip-lookup-popup').show();
			} else {
				alert('Failed to lookup IP: ' + response.data);
			}
		});
	});

    // Stats button handler
    $('#show-stats').click(function() {
        const reportElements = document.querySelectorAll('.bm-status.reported');
        let allReports = [];
        
        reportElements.forEach(element => {
            const reports = JSON.parse(element.dataset.reports);
            const userRow = element.closest('tr');
            const reportedUser = {
                id: userRow.cells[0].textContent.trim(),
                name: userRow.cells[1].textContent.trim()
            };
            
            reports.forEach(report => {
                report.reportedUser = reportedUser;
                allReports.push(report);
            });
        });

        showStatsPopup(processReportStats(allReports));
    });

    // Reports popup handler
	window.showReportPopup = function(element) {
		const reports = JSON.parse(element.dataset.reports);
		const userRow = element.closest('tr');
		const reportedUser = {
			id: userRow.cells[0].textContent.trim(),
			name: userRow.cells[1].textContent.trim(),
			ip: userRow.cells[9].textContent.trim()
		};

		let content = '<div class="reports-popup">';
		content += '<button class="popup-close-btn" onclick="jQuery(\'#ip-lookup-popup\').hide();">×</button>';
		content += buildReportSummary(reports);
		content += buildReportDetails(reports, reportedUser);
		content += '</div>';
		
		jQuery('#ip-lookup-content').html(content);
		jQuery('#ip-lookup-popup').show();
	};

    // Helper function to build report summary
// Helper function to build report summary
function buildReportSummary(reports) {
    const totalReports = reports.reduce((sum, report) => sum + report.reporters.length, 0);
    return `
        <div class="reports-summary">
            <div class="reports-header">
                <div class="header-content">
                    <svg class="header-icon" viewBox="0 0 24 24" width="24" height="24">
                        <path fill="currentColor" d="M21 21H3V3h18v18zM5 19h14V5H5v14z M7 11h10v2H7v-2z M7 7h10v2H7V7z M7 15h7v2H7v-2z"/>
                    </svg>
                    <h3>Résumé des Signalements</h3>
                </div>
            </div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-content">
                        <div class="stat-icon">⚠️</div>
                        <span class="stat-label">Total des Signalements</span>
                        <span class="stat-value">${totalReports}</span>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-content">
                        <div class="stat-icon">📝</div>
                        <span class="stat-label">Messages Signalés</span>
                        <span class="stat-value">${reports.length}</span>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Helper function to format date in French
function formatFrenchDate(dateStr) {
    try {
        const date = new Date(dateStr);
        if (isNaN(date.getTime())) {
            return "Date invalide";
        }
        
        const day = String(date.getDate()).padStart(2, '0');
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const year = date.getFullYear();
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        
        return `${day}/${month}/${year} ${hours}:${minutes}`;
    } catch (e) {
        console.error('Date parsing error:', e);
        return "Date invalide";
    }
}

// Helper function to build reporter entry
	function buildReporterEntry(reporterData, reportedUser, messageId) {
		const statusColors = {
			'new': '#ff9800',
			'dismissed': '#9e9e9e',
			'resolved': '#4CAF50',
			'monitoring': '#2196F3',
			'user_banned': '#f44336'
		};

		const status = reporterData.status || 'new';
		
		return `
			<div class="report-entry">
				<div class="report-timestamp">
					<div class="timestamp-content">
						<div class="calendar-icon">📅</div>
						${formatFrenchDate(reporterData.time)}
					</div>
				</div>
				
				<div class="users-info">
					<div class="reporter">
						<div class="user-header">
							<div class="user-icon">👤</div>
							<h4>Signalé par:</h4>
						</div>
						<div class="user-details">
							${reporterData.reporter_name} (ID: ${reporterData.reporter_id})
						</div>
					</div>
					<div class="reported">
						<div class="user-header">
							<div class="user-icon">⚠️</div>
							<h4>Utilisateur Signalé:</h4>
						</div>
						<div class="user-details">
							${reportedUser.name} (ID: ${reportedUser.id})
						</div>
					</div>
				</div>
				
				<div class="report-details">
					<div class="details-header">
						<div class="details-icon">📝</div>
						<strong>Description:</strong>
					</div>
					<div class="details-content">
						${reporterData.description}
					</div>
				</div>
				
				<div class="report-category">
					<div class="category-icon">🏷️</div>
					<strong>Catégorie:</strong> ${reporterData.category}
				</div>
				
				<div class="report-status" style="margin-top: 10px;">
					<div class="status-content">
						<strong>Status:</strong>
						<span class="status-badge" style="background-color: ${statusColors[status]}">
							${status.toUpperCase()}
						</span>
						<select class="status-update" onchange="updateReportStatus(${messageId}, ${reporterData.reporter_id}, this.value)">
							<option value="">Changer le status...</option>
							<option value="new">Nouveau</option>
							<option value="dismissed">Rejeté</option>
							<option value="resolved">Résolu</option>
							<option value="monitoring">Surveillance</option>
							<option value="user_banned">Utilisateur Banni</option>
						</select>
					</div>
				</div>
				
				<div class="action-buttons">
					<button class="button delete-report" onclick="deleteReport(${messageId}, ${reporterData.reporter_id})">
						<span class="button-icon">🗑️</span>
						Supprimer le Signalement
					</button>
					${reportedUser.ip ? `
						<button class="button ban-ip" onclick="banIP('${reportedUser.ip}')">
							<span class="button-icon">🚫</span>
							Bannir IP
						</button>
					` : ''}
				</div>
			</div>
		`;
	}

	// Function to build report details
	function buildReportDetails(reports, reportedUser) {
		return reports.map((report, index) => `
			<div class="report-message-group">
				<div class="message-info">
					<strong>Message ID:</strong> ${report.message_id}<br>
					<strong>Contenu:</strong> ${report.content}
				</div>
				
				<div class="reporters-list">
					<h5>Signalements (${report.reporters.length}):</h5>
					${report.reporters.map(reporterData => buildReporterEntry(reporterData, reportedUser, report.message_id)).join('')}
				</div>
			</div>
			${index < reports.length - 1 ? '<hr>' : ''}
		`).join('');
	}

	// Function to show report popup
	window.showReportPopup = function(element) {
		const reports = JSON.parse(element.dataset.reports);
		const userRow = element.closest('tr');
		const reportedUser = {
			id: userRow.cells[0].textContent.trim(),
			name: userRow.cells[1].textContent.trim(),
			ip: userRow.cells[9].textContent.trim()
		};

		let content = '<div class="reports-popup">';
		content += '<button class="popup-close-btn" onclick="jQuery(\'#ip-lookup-popup\').hide();">×</button>';
		content += buildReportSummary(reports);
		content += buildReportDetails(reports, reportedUser);
		content += '</div>';
		
		jQuery('#ip-lookup-content').html(content);
		jQuery('#ip-lookup-popup').show();
	};

/* --- Function buildReportDetails ---
   HELPER FUNCTION TO BUILD REPORT DETAILS
----------------------------------------------- */
// Helper function to build report summary
function buildReportSummary(reports) {
    const totalReports = reports.reduce((sum, report) => sum + report.reporters.length, 0);
    return `
        <div class="reports-summary">
            <div class="reports-header">
                <div class="header-content">
                    <svg class="header-icon" viewBox="0 0 24 24" width="24" height="24">
                        <path fill="currentColor" d="M21 21H3V3h18v18zM5 19h14V5H5v14z M7 11h10v2H7v-2z M7 7h10v2H7V7z M7 15h7v2H7v-2z"/>
                    </svg>
                    <h3>Résumé des Signalements</h3>
                </div>
            </div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-content">
                        <div class="stat-icon">⚠️</div>
                        <span class="stat-label">Total des Signalements</span>
                        <span class="stat-value">${totalReports}</span>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-content">
                        <div class="stat-icon">📝</div>
                        <span class="stat-label">Messages Signalés</span>
                        <span class="stat-value">${reports.length}</span>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Helper function to format date in simple format
function formatFrenchDate(dateStr) {
    // French month names to numbers mapping
    const frenchMonths = {
        'janvier': '01', 'février': '02', 'mars': '03', 'avril': '04',
        'mai': '05', 'juin': '06', 'juillet': '07', 'août': '08',
        'septembre': '09', 'octobre': '10', 'novembre': '11', 'décembre': '12'
    };

    try {
        // Parse the French date string
        // Example: "décembre 3, 2024 1:13 pm"
        const parts = dateStr.toLowerCase().match(/(\w+)\s+(\d+),\s+(\d+)\s+(\d+):(\d+)\s+(am|pm)/);
        
        if (parts) {
            let [, month, day, year, hours, minutes, ampm] = parts;
            
            // Convert month name to number
            month = frenchMonths[month] || '01';
            
            // Pad the day with leading zero if needed
            day = day.padStart(2, '0');
            
            // Convert hours to 24-hour format
            hours = parseInt(hours);
            if (ampm === 'pm' && hours < 12) hours += 12;
            if (ampm === 'am' && hours === 12) hours = 0;
            hours = String(hours).padStart(2, '0');
            
            // Pad minutes with leading zero if needed
            minutes = minutes.padStart(2, '0');
            
            // Return formatted date
            return `${day}/${month}/${year} ${hours}:${minutes}`;
        }
        return "Format invalide";
    } catch (e) {
        console.error('Error formatting date:', e);
        return "Date invalide";
    }
}

// Helper function to build reporter entry
	function buildReporterEntry(reporterData, reportedUser, messageId) {
		const statusColors = {
			'new': '#ff9800',
			'dismissed': '#9e9e9e',
			'resolved': '#4CAF50',
			'monitoring': '#2196F3',
			'user_banned': '#f44336'
		};

		const status = reporterData.status || 'new';
		
		return `
			<div class="report-entry">
				<div class="report-timestamp">
					<div class="timestamp-content">
						<div class="calendar-icon">📅</div>
						${formatFrenchDate(reporterData.time)}
					</div>
				</div>
				
				<div class="users-info">
					<div class="reporter">
						<div class="user-header">
							<div class="user-icon">👤</div>
							<h4>Signalé par:</h4>
						</div>
						<div class="user-details">
							${reporterData.reporter_name} (ID: ${reporterData.reporter_id})
						</div>
					</div>
					<div class="reported">
						<div class="user-header">
							<div class="user-icon">⚠️</div>
							<h4>Utilisateur Signalé:</h4>
						</div>
						<div class="user-details">
							${reportedUser.name} (ID: ${reportedUser.id})
						</div>
					</div>
				</div>
				
				<div class="report-details">
					<div class="details-header">
						<div class="details-icon">📝</div>
						<strong>Description:</strong>
					</div>
					<div class="details-content">
						${reporterData.description}
					</div>
				</div>
				
				<div class="report-category">
					<div class="category-icon">🏷️</div>
					<strong>Catégorie:</strong> ${reporterData.category}
				</div>
				
				<div class="report-status" style="margin-top: 10px;">
					<div class="status-content">
						<strong>Status:</strong>
						<span class="status-badge" style="background-color: ${statusColors[status]}">
							${status.toUpperCase()}
						</span>
						<select class="status-update" onchange="updateReportStatus(${messageId}, ${reporterData.reporter_id}, this.value)">
							<option value="">Changer le status...</option>
							<option value="new">Nouveau</option>
							<option value="dismissed">Rejeté</option>
							<option value="resolved">Résolu</option>
							<option value="monitoring">Surveillance</option>
							<option value="user_banned">Utilisateur Banni</option>
						</select>
					</div>
				</div>
				
				<div class="action-buttons">
					<button class="button delete-report" onclick="deleteReport(${messageId}, ${reporterData.reporter_id})">
						<span class="button-icon">🗑️</span>
						Supprimer le Signalement
					</button>
					${reportedUser.ip ? `
						<button class="button ban-ip" onclick="banIP('${reportedUser.ip}')">
							<span class="button-icon">🚫</span>
							Bannir IP
						</button>
					` : ''}
				</div>
			</div>
		`;
	}

    // Stats processing function
	function processReportStats(reports) {
		let stats = {
			reportedUsers: {},
			reporters: {},
			categories: {}
		};

		// Cache for display names from the table
		const displayNameCache = new Map();
		
		// Build display name cache from table
		const rows = document.querySelectorAll('.wp-list-table tr');
		rows.forEach(row => {
			const id = row.cells[0]?.textContent.trim();
			const name = row.cells[1]?.textContent.trim();
			if (id && name) {
				displayNameCache.set(id, name);
			}
		});

		reports.forEach(report => {
			// Process reported users
			const reportedId = report.reportedUser.id;
			if (!stats.reportedUsers[reportedId]) {
				stats.reportedUsers[reportedId] = {
					count: 0,
					name: report.reportedUser.name
				};
			}
			stats.reportedUsers[reportedId].count += report.reporters.length;

			// Process reporters and categories
			report.reporters.forEach(reporter => {
				const reporterId = reporter.reporter_id;
				let reporterName = reporter.reporter_name;

				// For guest users (negative IDs), try to get name from table
				if (reporterId < 0) {
					const cachedName = displayNameCache.get(String(reporterId));
					if (cachedName) {
						reporterName = cachedName;
					}
				}

				if (!stats.reporters[reporterId]) {
					stats.reporters[reporterId] = {
						count: 0,
						name: reporterName
					};
				}
				stats.reporters[reporterId].count++;

				const category = reporter.category;
				stats.categories[category] = (stats.categories[category] || 0) + 1;
			});
		});

		return stats;
	}

    // Stats display function
	function showStatsPopup(stats) {
		const content = `
			<div class="reports-popup stats-popup">
				<button class="popup-close-btn" onclick="jQuery('#ip-lookup-popup').hide();">×</button>
				${buildStatsSection('Most Reported Users', stats.reportedUsers)}
				${buildStatsSection('Most Active Reporters', stats.reporters)}
				${buildCategoryStats(stats.categories)}
			</div>
		`;

		jQuery('#ip-lookup-content').html(content);
		jQuery('#ip-lookup-popup').show();
	}

    // Helper function to build stats section
	function buildStatsSection(title, data) {
		const items = Object.entries(data)
			.sort((a, b) => b[1].count - a[1].count)
			.slice(0, 20);

		return `
			<div class="stats-section">
				<h3>Top 20 ${title}</h3>
				<table class="wp-list-table widefat fixed striped">
					<thead>
						<tr>
							<th>User</th>
							<th>Count</th>
						</tr>
					</thead>
					<tbody>
						${items.map(([id, data]) => `
							<tr>
								<td>${data.name} (ID: ${id})</td>
								<td>${data.count}</td>
							</tr>
						`).join('')}
					</tbody>
				</table>
			</div>
		`;
	}

	// Helper function to build category stats
	function buildCategoryStats(categories) {
		// Define category icons mapping - using lowercase keys to match database values
		const categoryIcons = {
			'spam': '⚠️',
			'harassment': '🔪',
			'offensive': '💣',
			'inappropriate': '🔞',
			'other': '❓'
		};

		return `
			<div class="stats-section">
				<h3>Report History</h3>
				<table class="wp-list-table widefat fixed striped">
					<thead>
						<tr>
							<th>Category</th>
							<th>Count</th>
						</tr>
					</thead>
					<tbody>
						${Object.entries(categories)
							.sort((a, b) => b[1] - a[1])
							.map(([category, count]) => {
								// Convert category to lowercase for matching
								const categoryLower = category.toLowerCase();
								const icon = categoryIcons[categoryLower] || '';
								return `
									<tr>
										<td>
											<span style="font-size: 1.2em; margin-right: 8px; vertical-align: middle;">
												${icon}
											</span>
											${category}
										</td>
										<td>${count}</td>
									</tr>
								`;
							}).join('')}
					</tbody>
				</table>
			</div>
		`;
	}

    // Action handlers
    window.deleteReport = function(messageId, reporterId) {
        if (!confirm('Delete this report?')) return;
        
        $.post(ajaxurl, {
            action: 'bm_delete_report',
            message_id: messageId,
            reporter_id: reporterId,
            nonce: '<?php echo wp_create_nonce("bm_report_actions"); ?>'
        }).done(response => {
            if (response.success) {
                location.reload();
            } else {
                alert('Error deleting report');
            }
        });
    };
	
	window.updateReportStatus = function(messageId, reporterId, newStatus) {
		if (!newStatus) return;
		
		jQuery.post(ajaxurl, {
			action: 'bm_update_report_status',
			message_id: messageId,
			reporter_id: reporterId,
			status: newStatus,
			nonce: '<?php echo wp_create_nonce("bm_report_actions"); ?>'
		}).done(response => {
			if (response.success) {
				location.reload();
			} else {
				alert('Failed to update report status');
			}
		});
	};

    window.deleteMessage = function(messageId) {
        if (!confirm('Delete this message?')) return;
        
        $.post(ajaxurl, {
            action: 'bm_delete_message',
            message_id: messageId,
            nonce: '<?php echo wp_create_nonce("bm_report_actions"); ?>'
        }).done(response => {
            if (response.success) {
                location.reload();
            } else {
                alert('Error deleting message');
            }
        });
    };

    window.banIP = function(ip) {
        if (!confirm('Are you sure you want to ban this IP: ' + ip + '?')) return;

        $.post(ajaxurl, {
            action: 'bm_ban_ip',
            ip: ip,
            nonce: '<?php echo wp_create_nonce('bm_ban_ip'); ?>'
        }).done(response => {
            if (response.success) {
                alert('IP has been banned successfully!');
                location.reload();
            } else {
                alert('Failed to ban IP: ' + (response.data || 'Unknown error'));
            }
        }).fail((xhr, status, error) => {
            console.error('Ban request failed:', error);
            alert('Failed to ban IP: ' + error);
        });
    };
});
</script>		


<?php
}
/* --- Color by sexe and showing users datas ---
   PARTICIPANT CHAT LIST CUSTOMIZATION
----------------------------------------------- */
add_filter('better_messages_rest_user_item', function($item, $user_id, $include_personal) {
    global $wpdb;
    $users_table = bm_get_table('users');
    
    $user_data = $wpdb->get_row($wpdb->prepare(
        "SELECT age, departement, ville, sexe 
        FROM {$users_table} 
        WHERE ID = %d", 
        $user_id
    ));

    if ($user_data) {
        $item['age'] = $user_data->age;
        $item['departement'] = $user_data->departement;
        $item['ville'] = $user_data->ville;
        $item['sexe'] = $user_data->sexe;
    }

    return $item;
}, 10, 3);


/* --- Function prepare_guest_registration_data ---
   VALIDATE AND FORMAT GUEST REGISTRATION DATA
----------------------------------------------- */
add_filter('better_messages_guest_register_data', 'prepare_guest_registration_data', 5, 2);
function prepare_guest_registration_data($guest_data, $register_data) {
    // Format ville (city) to meet database constraints
    if (isset($guest_data['ville'])) {
        $ville = $guest_data['ville'];
        
        // Remove any special characters and normalize spaces
        $ville = preg_replace('/[^A-Za-z\s]/', '', $ville);
        $ville = trim(preg_replace('/\s+/', ' ', $ville));
        
        // Convert to uppercase
        $ville = strtoupper($ville);
               
        // Truncate to maximum 25 characters if needed
        if (strlen($ville) > 25) {
            $ville = substr($ville, 0, 25);
        }
        
        $guest_data['ville'] = $ville;
    }

    // Set initial status based on gender
    if (isset($guest_data['sexe'])) {
        $gender_to_status = [
            'Homme' => 'online',
            'Femme' => 'away',
            'Trans/Trav' => 'dnd'
        ];

        $initial_status = isset($gender_to_status[$guest_data['sexe']]) 
            ? $gender_to_status[$guest_data['sexe']] 
            : 'online';

        $guest_data['meta'] = json_encode(['bpbm_online_status' => $initial_status]);
    }
	    // Add user agent to guest data
    $guest_data['user_agent'] = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
	
    return $guest_data;
}


/* --- Function handle_guest_status_change ---
   HANDLE GUEST STATUS CHANGES AND GENDER SYNC
----------------------------------------------- */
add_filter('better_messages_user_config_save', 'handle_guest_status_change', 10, 2);
function handle_guest_status_change($response, $params) {
    // Check if this is a guest user
    $user_id = Better_Messages()->functions->get_current_user_id();
    if ($user_id >= 0) {
        return $response;
    }

    // Check if this is an online status update
    if (!isset($params['option']) || $params['option'] !== 'online_status') {
        return $response;
    }

    $guest_id = abs($user_id);
    $new_status = sanitize_text_field($params['value']);

    // Map status to gender
    $status_to_gender = [
        'online' => 'Homme',
        'away'   => 'Femme',
        'dnd'    => 'Trans/Trav'
    ];

    $new_gender = isset($status_to_gender[$new_status]) ? $status_to_gender[$new_status] : null;

    if ($new_gender) {
        global $wpdb;
        
        // Update both status and gender
        $result = $wpdb->update(
            bm_get_table('guests'),
            [
                'meta' => json_encode(['bpbm_online_status' => $new_status]),
                'sexe' => $new_gender
            ],
            ['id' => $guest_id],
            ['%s', '%s'],
            ['%d']
        );

        if ($result !== false) {
            // Clear cache
            wp_cache_delete('guest_user_' . $guest_id, 'bm_messages');
            
            // Trigger update events
            do_action('better_messages_guest_updated', $guest_id);
            do_action('better_messages_user_updated', $user_id);

            return [
                'message' => $new_status,
                'update'  => true
            ];
        }
    }

    return $response;
}



/* --- Function get_device_type ---
   DETECT DEVICE TYPE FROM USER AGENT
----------------------------------------------- */
function get_device_type($user_agent) {
    // If no user agent is provided, return 'unknown'
    if (empty($user_agent)) {
        return 'unknown';
    }

    // List of common mobile keywords in user agents
    $mobile_keywords = [
        'Mobile', 'Android', 'iPhone', 'iPad', 'Windows Phone',
        'webOS', 'BlackBerry', 'iPod', 'Opera Mini', 'IEMobile'
    ];

    // Check for mobile keywords
    foreach ($mobile_keywords as $keyword) {
        if (stripos($user_agent, $keyword) !== false) {
            return 'mobile';
        }
    }

    // If no mobile keywords found, assume it's a desktop
    return 'desktop';
}



/* --- Function sync_user_status_with_gender ---
   SYNC USER STATUS WITH GENDER FOR WP USERS
----------------------------------------------- */
function sync_user_status_with_gender($meta_id, $user_id, $meta_key, $meta_value) {
    // Only proceed if this is a status change
    if ($meta_key !== 'bpbm_online_status') {
        return;
    }

    // Status to gender mapping
    $status_to_gender = [
        'online' => 'Homme',
        'away'   => 'Femme',
        'dnd'    => 'Trans/Trav'
    ];

    // Get corresponding gender for the status
    $new_gender = isset($status_to_gender[$meta_value]) ? $status_to_gender[$meta_value] : null;

    if ($new_gender) {
        global $wpdb;

        // Update xprofile data table
        $wpdb->update(
            $wpdb->prefix . 'bp_xprofile_data',
            ['value' => $new_gender],
            [
                'user_id' => $user_id,
                'field_id' => 3  // field_id for gender
            ]
        );

        // Update user index table
        $wpdb->query($wpdb->prepare(
            "INSERT INTO " . bm_get_table('users') . " 
            (ID, sexe, last_changed) 
            VALUES (%d, %s, %d) 
            ON DUPLICATE KEY UPDATE 
            sexe = VALUES(sexe),
            last_changed = VALUES(last_changed)",
            $user_id,
            $new_gender,
            Better_Messages()->functions->get_microtime()
        ));

        // Clear any cached user data
        wp_cache_delete($user_id, 'bm_messages');

        // Trigger necessary update events
        do_action('better_messages_user_updated', $user_id);
        do_action('xprofile_updated_profile', $user_id, [3], null, [], ['3' => $new_gender]);
    }
}
add_action('updated_user_meta', 'sync_user_status_with_gender', 10, 4);

/* --- Function modify_sync_user_data ---
   MODIFY SYNC USER DATA FOR INITIAL STATUS
----------------------------------------------- */
function modify_sync_user_data($user_id) {
    if ($user_id < 0) {
        return; // Skip for guest users as they have their own handling
    }

    global $wpdb;

    // Get current gender from xprofile
    $gender = $wpdb->get_var($wpdb->prepare(
        "SELECT value 
        FROM {$wpdb->prefix}bp_xprofile_data 
        WHERE field_id = 3 
        AND user_id = %d",
        $user_id
    ));

    // Gender to status mapping
    $gender_to_status = [
        'Homme' => 'online',
        'Femme' => 'away',
        'Trans/Trav' => 'dnd'
    ];

    // If we have a valid gender, set the corresponding status
    if (isset($gender_to_status[$gender])) {
        update_user_meta($user_id, 'bpbm_online_status', $gender_to_status[$gender]);
    }
}
add_action('better_messages_user_updated', 'modify_sync_user_data', 20);


/* --- Function handle_status_change_rest ---
   HANDLE STATUS CHANGES VIA REST API
----------------------------------------------- */
function handle_status_change_rest($response, $params) {
    if (!isset($params['option']) || $params['option'] !== 'online_status') {
        return $response;
    }

    $user_id = Better_Messages()->functions->get_current_user_id();
    
    // Skip for guest users as they have their own handling
    if ($user_id < 0) {
        return $response;
    }

    $new_status = sanitize_text_field($params['value']);

    // Map status to gender
    $status_to_gender = [
        'online' => 'Homme',
        'away'   => 'Femme',
        'dnd'    => 'Trans/Trav'
    ];

    if (isset($status_to_gender[$new_status])) {
        update_user_meta($user_id, 'bpbm_online_status', $new_status);
        
        return [
            'message' => $new_status,
            'update'  => true
        ];
    }

    return $response;
}
add_filter('better_messages_user_config_save', 'handle_status_change_rest', 10, 2);



/* --- Filtre register data ---
   DEBUG FOR GUEST USER AGENT
----------------------------------------------- */
add_filter('better_messages_guest_register_data', function($guest_data, $register_data) {
    // Debug log incoming data
    error_log('Processing guest registration data - Input data: ' . print_r($register_data, true));
    error_log('Initial guest data: ' . print_r($guest_data, true));

    // Ensure user agent is captured
    if (!isset($guest_data['user_agent']) || empty($guest_data['user_agent'])) {
        $guest_data['user_agent'] = isset($_SERVER['HTTP_USER_AGENT']) ? 
            sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : '';
    }

    // Clean and validate other fields if needed
    if (isset($guest_data['ville'])) {
        $guest_data['ville'] = trim(strtoupper(preg_replace('/[^A-Za-z\s]/', '', $guest_data['ville'])));
        if (strlen($guest_data['ville']) > 25) {
            $guest_data['ville'] = substr($guest_data['ville'], 0, 25);
        }
    }

    if (isset($guest_data['sexe']) && !in_array($guest_data['sexe'], ['Homme', 'Femme', 'Trans/Trav'])) {
        $guest_data['sexe'] = null;
    }

    if (isset($guest_data['age'])) {
        $age = intval($guest_data['age']);
        if ($age < 18 || $age > 99) {
            $guest_data['age'] = null;
        }
    }

    // Set initial status based on gender if not set
    if (isset($guest_data['sexe']) && (!isset($guest_data['meta']) || empty($guest_data['meta']))) {
        $gender_to_status = [
            'Homme' => 'online',
            'Femme' => 'away',
            'Trans/Trav' => 'dnd'
        ];
        
        $initial_status = isset($gender_to_status[$guest_data['sexe']]) ? 
            $gender_to_status[$guest_data['sexe']] : 'online';
            
        $guest_data['meta'] = json_encode(['bpbm_online_status' => $initial_status]);
    }
    
    // Debug log processed data
    error_log('Processed guest data: ' . print_r($guest_data, true));
    
    return $guest_data;
}, 10, 2);


/* --- flush_all_reports ---
   BUTTON DELETE ALL REPORTS
----------------------------------------------- */
function flush_all_reports() {
    global $wpdb;
    
    try {
        // Start transaction
        $wpdb->query('START TRANSACTION');

        // Get all message IDs with reports
        $messages_with_reports = $wpdb->get_col("
            SELECT DISTINCT bm_message_id 
            FROM " . bm_get_table('meta') . "
            WHERE meta_key = 'user_reports'
        ");

        if (empty($messages_with_reports)) {
            $wpdb->query('COMMIT');
            return 0;
        }

        // Delete all report metadata
        $deleted = $wpdb->query("
            DELETE FROM " . bm_get_table('meta') . "
            WHERE meta_key = 'user_reports'
        ");

        if ($deleted === false) {
            throw new Exception('Failed to delete reports');
        }

        // Commit transaction
        $wpdb->query('COMMIT');

        // Clear any caches related to these messages
        foreach ($messages_with_reports as $message_id) {
            wp_cache_delete($message_id, 'bm_message_meta');
        }

        return count($messages_with_reports);

    } catch (Exception $e) {
        // If there's an error, rollback the transaction
        $wpdb->query('ROLLBACK');
        error_log('Error flushing reports: ' . $e->getMessage());
        return false;
    }
}

function get_total_reports_count() {
    global $wpdb;
    
    $count = $wpdb->get_var("
        SELECT COUNT(DISTINCT bm_message_id) 
        FROM " . bm_get_table('meta') . "
        WHERE meta_key = 'user_reports'
    ");

    return (int)$count;
}







/* --- function custom_better_messages_styles ---
   GROS BOUTON CONNEXION GUESTS
----------------------------------------------- */
function custom_better_messages_styles() {
    if (class_exists('Better_Messages')) {
        ?>
        <style>
            /* Style for the continue button when user has filled the form */
            .bm-guest-form .bm-button {
                background-color: #ed0058 !important;
                color: #ffffff !important;
                padding: 12px 24px !important;
                font-size: 1.1em !important;
                font-weight: bold !important;
                border: none !important;
                border-radius: 4px !important;
                cursor: pointer !important;
                width: 100% !important;
                max-width: 300px !important;
                margin: 10px auto !important;
                display: block !important;
                text-align: center !important;
                text-decoration: none !important;
            }

            /* Hover state */
            .bm-guest-form .bm-button:hover {
                background-color: #cc004c !important;
            }

            /* Active state */
            .bm-guest-form .bm-button:active {
                background-color: #b60044 !important;
            }

            /* Disabled state */
            .bm-guest-form .bm-button:disabled {
                background-color: #ff799b !important;
                cursor: not-allowed !important;
            }
        </style>
        <?php
    }
}
add_action('wp_head', 'custom_better_messages_styles');

// Optional: Filter to modify the button text
function custom_better_messages_button_text($translations, $text, $domain) {
    if ($domain === 'bp-better-messages' && $text === 'Continue') {
        return 'Continuer Sans Inscription';
    }
    return $translations;
}
add_filter('gettext', 'custom_better_messages_button_text', 20, 3);

// Optional: Enqueue custom JavaScript if needed
function custom_better_messages_scripts() {
    if (class_exists('Better_Messages')) {
        ?>
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Check if all required fields are present
            const hasAllFields = localStorage.getItem("name") && 
                               localStorage.getItem("age") && 
                               localStorage.getItem("departement") && 
                               localStorage.getItem("ville") && 
                               localStorage.getItem("sexe");

            if (hasAllFields) {
                // Add any additional JavaScript customizations here
                const guestButton = document.querySelector('.bm-guest-form .bm-button');
                if (guestButton) {
                    guestButton.style.backgroundColor = '#ed0058';
                    // Add any other dynamic style modifications
                }
            }
        });
        </script>
        <?php
    }
}
add_action('wp_footer', 'custom_better_messages_scripts');


/* --- Better_Messages_User_Toxicity ---
   TOXICITY HANDLES AND RULES
----------------------------------------------- */
class Better_Messages_User_Toxicity {
    private static $instance = null;
    private $toxicity_table;
    private $users_index_table;
    private $guests_table;

    public static function instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function __construct() {
        global $wpdb;
        $this->toxicity_table = $wpdb->prefix . 'bm_user_toxicity';
        $this->users_index_table = $wpdb->prefix . 'bm_user_index';
        $this->guests_table = $wpdb->prefix . 'bm_guests';

        // Hook into report creation
        add_action('better_messages_message_reported', array($this, 'handle_report'), 10, 6);
        
        // Hook into message sending
        add_action('messages_message_sent', array($this, 'update_message_count'), 10, 1);
        
        // Hook into user registration (both regular and guest)
        add_action('better_messages_user_created', array($this, 'initialize_user_toxicity'), 10, 1);
        add_action('better_messages_guest_registered', array($this, 'initialize_guest_toxicity'), 10, 1);
    }

    private function sync_user_message_count($user_id) {
        global $wpdb;
        
        $message_count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT id) 
             FROM " . bm_get_table('messages') . "
             WHERE sender_id = %d",
            $user_id
        ));
        
        $wpdb->query($wpdb->prepare(
            "UPDATE {$this->toxicity_table} 
             SET message_count = %d 
             WHERE user_id = %d",
            (int)$message_count,
            $user_id
        ));
        
        return (int)$message_count;
    }

    public function get_user_display_name($user_id) {
        global $wpdb;
        
        if ($user_id > 0) {
            return $wpdb->get_var($wpdb->prepare(
                "SELECT display_name FROM {$this->users_index_table} WHERE ID = %d",
                $user_id
            ));
        } else {
            $guest_id = abs($user_id);
            return $wpdb->get_var($wpdb->prepare(
                "SELECT name FROM {$this->guests_table} WHERE id = %d",
                $guest_id
            ));
        }
    }

    public function initialize_user_toxicity($user_id) {
        global $wpdb;
        
        $message_count = $this->sync_user_message_count($user_id);
        
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT user_id FROM {$this->toxicity_table} WHERE user_id = %d",
            $user_id
        ));
        
        if (!$exists) {
            $wpdb->insert(
                $this->toxicity_table,
                array(
                    'user_id' => $user_id,
                    'registration_date' => current_time('Y-m-d'),
                    'message_count' => $message_count,
                    'spam_reports' => 0,
                    'harassment_reports' => 0,
                    'offensive_reports' => 0,
                    'inappropriate_reports' => 0,
                    'other_reports' => 0,
                    'penalty_multiplier' => 1.0,
                    'toxicity_score' => 0.0
                ),
                array('%d', '%s', '%d', '%d', '%d', '%d', '%d', '%d', '%f', '%f')
            );
        }
    }

    public function initialize_guest_toxicity($guest_id) {
        $user_id = -1 * abs($guest_id);
        $this->initialize_user_toxicity($user_id);
    }

    public function update_message_count($message) {
        if (!isset($message->sender_id)) {
            return;
        }
        
        global $wpdb;
        $user_id = $message->sender_id;
        
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT user_id FROM {$this->toxicity_table} WHERE user_id = %d",
            $user_id
        ));
        
        if (!$exists) {
            $this->initialize_user_toxicity($user_id);
        }
        
        $wpdb->query($wpdb->prepare(
            "UPDATE {$this->toxicity_table} 
             SET message_count = message_count + 1 
             WHERE user_id = %d",
            $user_id
        ));
        
        $this->recalculate_user_score($user_id);
    }

    private function calculate_report_impact($report_count) {
        // First report has less impact (30%), increases gradually
        return min(1.0, 0.3 + (0.1 * ($report_count - 1)));
    }

    private function get_reporter_credibility($reporter_id) {
        // Members have higher credibility than guests
        $base_credibility = ($reporter_id > 0) ? 1.0 : 0.6;
        
        // Get reporter's toxicity score
        global $wpdb;
        $reporter_toxicity = $wpdb->get_var($wpdb->prepare(
            "SELECT toxicity_score FROM {$this->toxicity_table} WHERE user_id = %d",
            $reporter_id
        ));
        
        // If reporter has high toxicity, reduce their credibility
        if ($reporter_toxicity !== null) {
            $credibility_factor = (100 - $reporter_toxicity) / 100;
            return $base_credibility * $credibility_factor;
        }
        
        return $base_credibility;
    }

    private function calculate_positive_credits($user_data) {
        $credits = 0;
        
        // Account age bonus
        $account_age_days = (time() - strtotime($user_data->registration_date)) / 86400;
        $credits += min(20, $account_age_days / 10); // Max 20 points for 200+ days
        
        // Regular activity bonus
        if ($account_age_days > 0) {
            $msg_per_day = $user_data->message_count / $account_age_days;
            if ($msg_per_day >= 5 && $msg_per_day <= 50) {
                $credits += 10; // Healthy activity level
            }
        }
        
        // Clean streak bonus
        if ($user_data->last_report_date) {
            $days_since_report = (time() - strtotime($user_data->last_report_date)) / 86400;
            $credits += min(15, $days_since_report / 10); // Max 15 points for 150+ clean days
        }
        
        return $credits;
    }

	private function calculate_toxicity_score($user_id) {
		global $wpdb;

		$user_data = $wpdb->get_row($wpdb->prepare(
			"SELECT * FROM {$this->toxicity_table} WHERE user_id = %d",
			$user_id
		));

		if (!$user_data) {
			return 0;
		}

		// Category weights
		$weights = [
			'spam' => 30,
			'harassment' => 30,
			'offensive' => 15,
			'inappropriate' => 15,
			'other' => 10
		];

		$weighted_reports = 0;
		$total_reports = 0;

		// Calculate weighted reports
		foreach ($weights as $category => $weight) {
			$column = $category . '_reports';
			$report_count = $user_data->$column;
			
			if ($report_count > 0) {
				// Calculate impact based on report count
				$impact = min(1.0, 0.2 + (0.1 * ($report_count - 1)));
				
				// Apply time decay if last report date exists
				if ($user_data->last_report_date) {
					$days_old = (time() - strtotime($user_data->last_report_date)) / 86400;
					if ($days_old > 180) {
						$impact *= 0.4; // 60% reduction after 180 days
					} elseif ($days_old > 90) {
						$impact *= 0.6; // 40% reduction after 90 days
					} elseif ($days_old > 30) {
						$impact *= 0.8; // 20% reduction after 30 days
					}
				}
				
				$weighted_reports += ($report_count * $weight * $impact);
				$total_reports += $report_count;
			}
		}

		// Message volume normalization
		$message_factor = max(1, log10($user_data->message_count + 1));
		$normalized_reports = $weighted_reports / $message_factor;

		// Calculate positive credits
		$credits = 0;

		// Account age bonus (max 20 points)
		$account_age_days = (time() - strtotime($user_data->registration_date)) / 86400;
		$credits += min(20, $account_age_days / 10);

		// Activity bonus (max 10 points)
		if ($account_age_days > 0) {
			$msg_per_day = $user_data->message_count / $account_age_days;
			if ($msg_per_day >= 5 && $msg_per_day <= 50) {
				$credits += 10;
			}
		}

		// Clean streak bonus (max 15 points)
		if ($user_data->last_report_date) {
			$days_since_report = (time() - strtotime($user_data->last_report_date)) / 86400;
			$credits += min(15, $days_since_report / 10);
		}

		// Calculate base score
		$base_score = min(100, $normalized_reports);
		$base_score = max(0, $base_score - $credits);

		// Apply IP-based adjustments via filter
		$final_score = apply_filters('better_messages_calculate_toxicity', $base_score, $user_id);

		// Ensure final score is between 0 and 95
		return round(min(95, max(0, $final_score)), 1);
	}

    private function recalculate_user_score($user_id) {
        global $wpdb;
        
        $new_score = $this->calculate_toxicity_score($user_id);
        
        $wpdb->update(
            $this->toxicity_table,
            ['toxicity_score' => $new_score],
            ['user_id' => $user_id],
            ['%f'],
            ['%d']
        );
        
        return $new_score;
    }

    public function get_toxicity_status($user_id) {
        global $wpdb;
        
        $user_data = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->toxicity_table} WHERE user_id = %d",
            $user_id
        ));

        if (!$user_data) {
            return [
                'score' => 0,
                'percentage' => 100,
                'level' => 'TRUSTED',
                'icon' => '⭐',
                'color' => '#2196F3',
                'details' => 'New user, no reports'
            ];
        }

        $total_reports = $user_data->spam_reports + 
                        $user_data->harassment_reports + 
                        $user_data->offensive_reports + 
                        $user_data->inappropriate_reports + 
                        $user_data->other_reports;

        $score = $this->calculate_toxicity_score($user_id);
        $reliability = max(0, 100 - $score);

        // Updated thresholds for more gradual progression
        if ($score <= 10) {
            return [
                'score' => $score,
                'percentage' => $reliability,
                'level' => 'TRUSTED',
                'icon' => '⭐',
                'color' => '#2196F3',
                'details' => sprintf(
                    'Trusted user (%d messages, reliability: %.1f%%)',
                    $user_data->message_count,
                    $reliability
                )
            ];
        } 
        else if ($score <= 30) {
            return [
                'score' => $score,
                'percentage' => $reliability,
                'level' => 'GOOD',
                'icon' => '✅',
                'color' => '#43a047',
                'details' => sprintf(
                    'Good standing (%d messages, reliability: %.1f%%)',
                    $user_data->message_count,
                    $reliability
                )
            ];
        }
        else if ($score <= 50) {
            return [
                'score' => $score,
                'percentage' => $reliability,
                'level' => 'NORMAL',
                'icon' => '📝',
                'color' => '#FF9800',
                'details' => sprintf(
                    'Regular user (%d messages, reliability: %.1f%%)',
                    $user_data->message_count,
                    $reliability
                )
            ];
        }
        else if ($score <= 70) {
            return [
                'score' => $score,
                'percentage' => $reliability,
                'level' => 'WARNING',
                'icon' => '⚠️',
                'color' => '#FF5722',
                'details' => sprintf(
                    'Warning: Multiple reports (%d messages, reliability: %.1f%%)',
                    $user_data->message_count,
                    $reliability
                )
            ];
        }
        else if ($score <= 85) {
            return [
                'score' => $score,
                'percentage' => $reliability,
                'level' => 'HIGH RISK',
                'icon' => '🚨',
                'color' => '#f44336',
                'details' => sprintf(
                    'High risk user (%d messages, reliability: %.1f%%)',
                    $user_data->message_count,
                    $reliability
                )
            ];
        }
        else {
            return [
                'score' => $score,
                'percentage' => $reliability,
                'level' => 'TOXIC',
                'icon' => '⛔',
                'color' => '#b71c1c',
                'details' => sprintf(
                    'Toxic behavior (%d messages, reliability: %.1f%%)',
                    $user_data->message_count,
                    $reliability
                )
            ];
        }
    }

	public function handle_report($message_id, $thread_id, $reporter_id, $category, $description, $reports) {
		global $wpdb;
		
		$message = Better_Messages()->functions->get_message($message_id);
		if (!$message || !isset($message->sender_id)) {
			return;
		}

		// Check if this exact report already exists
		$existing_reports = $reports; // Use the passed reports parameter instead
		if(isset($existing_reports[$reporter_id])) {
			return true; // Return true instead of false for existing reports
		}
        
        $message = Better_Messages()->functions->get_message($message_id);
        if (!$message || !isset($message->sender_id)) {
            return;
        }

        $user_id = $message->sender_id;
        
        // First sync message count
        $this->sync_user_message_count($user_id);
        
        // Ensure user exists in toxicity table
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT user_id FROM {$this->toxicity_table} WHERE user_id = %d",
            $user_id
        ));

        if (!$exists) {
            $this->initialize_user_toxicity($user_id);
        }

        $category_columns = [
            'spam' => 'spam_reports',
            'harassment' => 'harassment_reports',
            'offensive' => 'offensive_reports',
            'inappropriate' => 'inappropriate_reports',
            'other' => 'other_reports'
        ];

        if (isset($category_columns[$category])) {
            $column = $category_columns[$category];
            
            // Get reporter credibility
            $reporter_weight = $this->get_reporter_credibility($reporter_id);
            
            // Create transaction for atomic updates
            $wpdb->query('START TRANSACTION');
            
            try {
                // Update report counts and metadata
                $result = $wpdb->query($wpdb->prepare(
                    "UPDATE {$this->toxicity_table} 
                    SET 
                        {$column} = {$column} + 1,
                        last_report_date = %s,
                        penalty_multiplier = LEAST(penalty_multiplier * 1.1, 2.0)
                    WHERE user_id = %d",
                    current_time('Y-m-d H:i:s'),
                    $user_id
                ));

                if ($result === false) {
                    throw new Exception('Failed to update report counts');
                }

                // Save report metadata directly to the database
                $meta_table = bm_get_table('meta');
                $existing_reports = $wpdb->get_var($wpdb->prepare(
                    "SELECT meta_value FROM {$meta_table} 
                    WHERE bm_message_id = %d AND meta_key = 'user_reports'",
                    $message_id
                ));

                $report_data = $existing_reports ? maybe_unserialize($existing_reports) : array();
                $report_data[$reporter_id] = array(
                    'category' => $category,
                    'description' => $description,
                    'time' => current_time('mysql')
                );

                $meta_result = $wpdb->replace(
                    $meta_table,
                    array(
                        'bm_message_id' => $message_id,
                        'meta_key' => 'user_reports',
                        'meta_value' => maybe_serialize($report_data)
                    ),
                    array('%d', '%s', '%s')
                );

                if ($meta_result === false) {
                    throw new Exception('Failed to save report metadata');
                }

                // Calculate new toxicity score
                $new_score = $this->calculate_toxicity_score($user_id);
                
                // Update toxicity score
                $score_result = $wpdb->update(
                    $this->toxicity_table,
                    ['toxicity_score' => $new_score],
                    ['user_id' => $user_id],
                    ['%f'],
                    ['%d']
                );

                if ($score_result === false) {
                    throw new Exception('Failed to update toxicity score');
                }

                $wpdb->query('COMMIT');
                
                // Clear caches
                wp_cache_delete($message_id, 'bm_message_meta');
                wp_cache_delete('user_' . $user_id, 'bm_messages');

            } catch (Exception $e) {
                $wpdb->query('ROLLBACK');
                error_log('Better Messages Toxicity Error: ' . $e->getMessage());
                return false;
            }
        }

        return true;
    }



} // FIN de la CLASS Better_Messages_User_Toxicity 


    /**
     * Initialisations nécessaires
     */


// Initialize the toxicity tracking system
function Better_Messages_User_Toxicity() {
    return Better_Messages_User_Toxicity::instance();
}

// Initialize after Better Messages is loaded
add_action('plugins_loaded', function() {
    if (class_exists('Better_Messages')) {
        Better_Messages_User_Toxicity();
    }
}, 20);


// Initialize table tracking for specific users if needed
add_action('init', function() {
    if (class_exists('Better_Messages')) {
        $toxicity = Better_Messages_User_Toxicity();
        
        $toxicity->initialize_user_toxicity(20);
    }
});


    /**
     * Better_Messages_IP_Toxicity System
     */
class Better_Messages_IP_Toxicity {
    private static $instance = null;

    public static function instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Check IP location and get base penalty
     */
    public function get_location_penalty($ip) {
        $record = geoip_detect2_get_info_from_ip($ip);
        
        if (!$record || !$record->country || !$record->country->isoCode) {
            return 50.0; // Unknown location = high penalty
        }

        return ($record->country->isoCode !== 'FR') ? 50.0 : 0.0;
    }

    /**
     * Get all IPs used by a user within time period
     */
    private function get_user_ips($user_id, $hours = 24) {
        global $wpdb;
        
        $time_limit = date('Y-m-d H:i:s', strtotime("-{$hours} hours"));
        
        // For guests (negative user_id)
        if ($user_id < 0) {
            $guest_id = abs($user_id);
            $table = bm_get_table('guests');
            
            $ips = $wpdb->get_col($wpdb->prepare(
                "SELECT DISTINCT ip 
                FROM {$table} 
                WHERE id = %d 
                AND created_at >= %s",
                $guest_id,
                $time_limit
            ));
        } 
        // For registered users
        else {
            $table = bm_get_table('users');
            
            $ips = $wpdb->get_col($wpdb->prepare(
                "SELECT DISTINCT ip 
                FROM {$table} 
                WHERE ID = %d 
                AND last_activity >= %s",
                $user_id,
                $time_limit
            ));
        }

        return array_filter($ips); // Remove empty values
    }

    /**
     * Calculate IP multiplier based on number of IPs and time period
     */
    public function calculate_ip_multiplier($user_id) {
        // Regular members get minimal IP checking
        if ($user_id > 0) {
            return 1.0;
        }

        // Check IPs in last 24 hours
        $ips_24h = $this->get_user_ips($user_id, 24);
        $ip_count_24h = count($ips_24h);

        // Check IPs in last 72 hours
        $ips_72h = $this->get_user_ips($user_id, 72);
        $ip_count_72h = count($ips_72h);

        // Calculate multiplier based on IP counts
        if ($ip_count_24h >= 3) {
            // Check if any IP is non-French
            $has_non_french = false;
            foreach ($ips_24h as $ip) {
                if ($this->get_location_penalty($ip) > 0) {
                    $has_non_french = true;
                    break;
                }
            }
            
            if ($has_non_french) {
                return 'max'; // Special case for maximum penalty
            }
            return 2.0; // Severe multiplier for 3+ IPs in 24h
        }
        
        if ($ip_count_24h == 2) {
            return 1.5; // Moderate multiplier for 2 IPs in 24h
        }
        
        if ($ip_count_72h >= 4) {
            return 1.5; // Moderate multiplier for 4+ IPs in 72h
        }
        
        if ($ip_count_72h >= 2) {
            return 1.1; // Minor multiplier for 2-3 IPs in 72h
        }

        return 1.0; // Default multiplier
    }

    /**
     * Apply IP-based adjustments to toxicity score
     */
    public function adjust_toxicity_score($base_score, $user_id) {
        // Get current IP
        $current_ip = '';
        if ($user_id < 0) {
            global $wpdb;
            $guest_id = abs($user_id);
            $current_ip = $wpdb->get_var($wpdb->prepare(
                "SELECT ip FROM " . bm_get_table('guests') . " WHERE id = %d",
                $guest_id
            ));
        } else {
            $current_ip = get_user_meta($user_id, 'last_ip', true);
        }

        if (empty($current_ip)) {
            return min(95, $base_score + 50); // High penalty for no IP
        }

        // Get location penalty
        $location_penalty = $this->get_location_penalty($current_ip);
        
        // Get IP multiplier
        $ip_multiplier = $this->calculate_ip_multiplier($user_id);
        
        // Calculate final score
        if ($ip_multiplier === 'max') {
            return 95; // Maximum penalty
        }

        $adjusted_score = ($base_score + $location_penalty) * $ip_multiplier;
        
        // Cap at 95 to leave room for future increases
        return min(95, $adjusted_score);
    }
}

// Initialize the IP toxicity system
function Better_Messages_IP_Toxicity() {
    return Better_Messages_IP_Toxicity::instance();
}

// Add to the main toxicity calculation
add_filter('better_messages_calculate_toxicity', function($score, $user_id) {
    $ip_toxicity = Better_Messages_IP_Toxicity();
    return $ip_toxicity->adjust_toxicity_score($score, $user_id);
}, 10, 2);




/**
 * Report rate limiting for users
 */
