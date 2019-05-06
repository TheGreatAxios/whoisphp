<?php


/*

WhoisInformation.Net #
###############################

You may configure the script by editing the values below.

Connection timeout.  maximum length of time in seconds for a response from a WHOIS server.  

*/

$connection_timeout = 15;

/*

Default extension.  If a default extension is configured, the lookup form will show that extension already selected. Example: $default_extension = ".com.au";  Default: $default_extension = "";

*/

$default_extension = "";

/*

Title.

*/

$header_title = "WhoisInformation.NET";

/*

Header title URL. 

*/

$header_title_url = $_SERVER["PHP_SELF"];

/*

Use internal style sheet. To disable it, change the 1 to 0

*/

$internal_style_sheet = 1;

/*

Use external style sheet. To do so change the 0 to 1

*/

$external_style_sheet = 0;



$body_font_family = "verdana,arial,sans-serif";
$body_font_size = "80%";
$body_background = "#d4d4d4";
$body_color = "#000000";
$body_padding = "0";
$body_border = "0";
$body_margin = "20px";

$hr_background = "#d4d4d4";
$hr_color = "#d4d4d4";

$link_text_decoration = "underline";
$link_color = "#0000ff";
$link_background = "#ffffff";

$link_hover_text_decoration = "underline";
$link_hover_color = "#0000ff";
$link_hover_background = "#ffffff";

$link_visited_text_decoration = "underline";
$link_visited_color = "#0000ff";
$link_visited_background = "#ffffff";

$link_active_text_decoration = "underline";
$link_active_color = "#0000ff";
$link_active_background = "#ffffff";

$container_background = "#ffffff";

$title_link_font_size = "25px";
$title_link_color = "#000000";
$title_link_text_decoration = "none";
$title_link_background = "#ffffff";

$other_link_font_size = "22px";
$other_link_color = "#000000";
$other_link_text_decoration = "none";
$other_link_background = "#ffffff";

$error_messages_color = "#ff0000";

$form_background = "#f2f2f2";

$form_border = "#d4d4d4";

$response_display_background = "#f2f2f2";

$domain_available_message_color = "#009900";



#           END OF CONFIGURATION OPTIONS           #


$supported_extensions = array(
    ".com" => array("whois_server" => "whois.verisign-grs.com"),
    ".net" => array("whois_server" => "whois.verisign-grs.com"),
    ".org" => array("whois_server" => "whois.publicinterestregistry.net"),
    ".info" => array("whois_server" => "whois.afilias.info"),
    ".biz" => array("whois_server" => "whois.biz"),
    ".co.uk" => array("whois_server" => "whois.nic.uk"),
    ".ca" => array("whois_server" => "whois.cira.ca"),
    ".com.au" => array("whois_server" => "whois.audns.net.au"),


);

$extensions_array = array_keys($supported_extensions);

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    // Trim post values and make lower-case

    foreach ($_POST as $key => $value) {
        $_POST[$key] = strtolower(trim($value));
    }

    // Check submitted values

    $errors = array();

    // Check domain and extension are present and have values
    if (!isset($_POST['domain']) || empty($_POST['domain']) || !isset($_POST['extension']) || empty($_POST['extension'])) {
        $errors[] = "Enter the domain name you wish you query";
    }

    // Check domain
    if (isset($_POST['domain']) && !empty($_POST['domain'])) {

        // Remove spaces
        $_POST['domain'] = str_replace(" ", "", $_POST['domain']);

        // Check length of domain
        if (strlen($_POST['domain']) > 63) {
            $errors[] = "Domain name is too long. Please use a maximum of 63 characters.";
        }

        // Check domain for acceptable characters
        if (!preg_match('/^[0-9a-zA-Z-]+$/i', $_POST['domain'])) {
            $errors[] = "Domain may only contain English numbers, letters or hyphens.";
        }

        // Check domain for begin or end with a hyphen
        if (substr(stripslashes($_POST['domain']), 0, 1) == "-" || substr(stripslashes($_POST['domain']), -1) == "-") {
            $errors[] = "Domain names may not begin or end with a hyphen.";
        }
    }

    // Check extension is acceptable. lower case at this point for testing in the case-sensitive in_array().
    if (!in_array($_POST['extension'], $extensions_array)) {
        $errors[] = "This domain extension is not currently supported.";
    }

    if (!count($errors)) {
        $domain = $_POST['domain'];
        $extension = $_POST['extension'];

        $whois_servers = array(
            "whois.afilias.info" => array("port" => "43","query_begin" => "","query_end" => "\r\n","redirect" => "0","redirect_string" => "","no_match_string" => "NOT FOUND","match_string" => "Domain Name:","encoding" => "UTF-8"),
            "whois.audns.net.au" => array("port" => "43","query_begin" => "","query_end" => "\r\n","redirect" => "0","redirect_string" => "","no_match_string" => "No Data Found","match_string" => "Domain Name:","encoding" => "UTF-8"),
            "whois.biz" => array("port" => "43","query_begin" => "","query_end" => "\r\n","redirect" => "0","redirect_string" => "","no_match_string" => "Not found:","match_string" => "Registrant Name:","encoding" => "iso-8859-1"),
            "whois.cira.ca" => array("port" => "43","query_begin" => "","query_end" => "\r\n","redirect" => "0","redirect_string" => "","no_match_string" => "Domain status:         available","match_string" => "Domain status:         registered","encoding" => "UTF-8"),
            "whois.nic.uk" => array("port" => "43","query_begin" => "","query_end" => "\r\n","redirect" => "0","redirect_string" => "","no_match_string" => "No match for","encoding" => "iso-8859-1"),
            "whois.publicinterestregistry.net" => array("port" => "43","query_begin" => "","query_end" => "\r\n","redirect" => "0","redirect_string" => "","no_match_string" => "NOT FOUND","encoding" => "iso-8859-1"),
            "whois.verisign-grs.com" => array("port" => "43","query_begin" => "domain ","query_end" => "\r\n","redirect" => "1","redirect_string" => "Registrar WHOIS Server:","no_match_string" => "No match for domain","encoding" => "iso-8859-1")

                );

        $whois_server = $supported_extensions[$extension]['whois_server'];
        $port = $whois_servers[$whois_server]['port'];
        $query_begin = $whois_servers[$whois_server]['query_begin'];
        $query_end = $whois_servers[$whois_server]['query_end'];
        $whois_redirect_check = $whois_servers[$whois_server]['redirect'];
        $whois_redirect_string = $whois_servers[$whois_server]['redirect_string'];
        $no_match_string = $whois_servers[$whois_server]['no_match_string'];
        $encoding = $whois_servers[$whois_server]['encoding'];

        $whois_redirect_server = "";
        $response = "";
        $line = "";

        $fp = fsockopen($whois_server, $port, $errno, $errstr, $connection_timeout);

        if (!$fp) {
            print "fsockopen() error when trying to connect to {$whois_server}<br><br>Error number: ".$errno."<br>"."Error message: ".$errstr;
            exit;
        }

        fputs($fp, $query_begin.$domain.$extension.$query_end);

        while (!feof($fp)) {
            $line = fgets($fp);

            $response .= $line;

            // Check for whois redirect server.
            if ($whois_redirect_check && stristr($line, $whois_redirect_string)) {
                $whois_redirect_server = trim(str_replace($whois_redirect_string, "", $line));
                break;
            }
        }

        fclose($fp);

        // Query redirect server if set.

        if ($whois_redirect_server) {
            // Query the redirect server.  Might be different values for port etc, so give the option to change them from those set previously.  Using defaults below.

            $whois_server = $whois_redirect_server;
            $port = "43";
            $connection_timeout = 5;
            $query_begin = "";
            $query_end = "\r\n";

            $response = "";

            $fp = fsockopen($whois_server, $port, $errno, $errstr, $connection_timeout);

            if (!$fp) {
                print "fsockopen() error when trying to connect to {$whois_server}<br><br>Error number: ".$errno."<br>"."Error message: ".$errstr;
                exit;
            }

            fputs($fp, $query_begin.$domain.$extension.$query_end);

            while (!feof($fp)) {
                $response .= fgets($fp);
            }

            fclose($fp);
        }

        // Check result for no-match phrase.
        $domain_registered_message = "";
        if (stristr($response, $no_match_string)) {
            $domain_registered_message = "<span style=\"color:#009900\"><b>" . htmlentities($domain . $extension) . " is not registered</b><BR/><b><a href=\"http://www.kqzyfj.com/click-9079917-514796\" target=\"_top\">Purchase this domain now!</a><img src=\"http://www.awltovhc.com/image-9079917-514796\" width=\"1\" height=\"1\" border=\"0\"/></b></span>";
        } else {
            $domain_registered_message = "<b>" . htmlentities($domain . $extension) . " is registered, Try another search.</b>";
        }
    }
}

// Set a default encoding for the form page.  If a WHOIS server uses a particular encoding it will be set above if the form is posted without errors.
if (!isset($encoding)) {
    $encoding = "UTF-8";
}

?>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=<?php print $encoding ?>">
    <title>WhoisInformation.NET - whois data lookup</title>
    <meta name="description" content="WHOIS data information search">
    <meta name="keywords" content="whois,whoisquery,search,domain">
    <?php

    // Use internal or external style sheet.

    if ($internal_style_sheet) {
        print "<style type=\"text/css\">\n";
        print "body{font-family:{$body_font_family}; font-size:{$body_font_size}; background:{$body_background}; color:{$body_color}; padding:{$body_padding}; border:{$body_border}; margin:{$body_margin};}\n";
        print "hr{border:0; height:1px; background:{$hr_background}; color:{$hr_color};}\n";
        print "a:link{text-decoration:{$link_text_decoration}; color:{$link_color}; background:{$link_background};}\n";
        print "a:hover{text-decoration:{$link_hover_text_decoration}; color:{$link_hover_color}; background:{$link_hover_background};}\n";
        print "a:visited{text-decoration:{$link_visited_text_decoration}; color:{$link_visited_color}; background:{$link_visited_background};}\n";
        print "a:active{text-decoration:{$link_active_text_decoration}; color:{$link_active_color}; background:{$link_active_background};}\n";
        print ".container{width:800px; background:{$container_background}; word-wrap:break-word; padding:20px; margin-left:auto; margin-right:auto;}\n";
        print "#title_link{font-size:{$title_link_font_size}; color:{$title_link_color}; text-decoration:{$title_link_text_decoration}; background:{$title_link_background};}\n";
		print "#other_link{font-size:{$other_link_font_size}; color:{$other_link_color}; text-decoration:{$other_link_text_decoration}; background:{$other_link_background};}\n";
        print ".error_messages{color:{$error_messages_color};}\n";
        print "#lookup_form{display:inline-block; background:{$form_background}; padding:5px; border:1px solid {$form_border};}\n";
        print ".response_display{background:{$response_display_background}; width:600px; padding:10px; word-wrap:break-word;}\n";
        print ".domain_available_message{color:{$domain_available_message_color};}\n";
        print "</style>\n";
    } elseif ($external_style_sheet) {
        print "<link rel=\"stylesheet\" type=\"text/css\" href=\"{$external_style_sheet_location}\">";
    }

    ?>
</head>
<body>
    <div class="container">
        <table style="width:100%; border-collapse: collapse;">
            <tr>
                <td style="text-align:left; vertical-align:middle; padding:0px;">
                   <a href="<?php print htmlspecialchars($header_title_url) ?>" id="title_link"><b><?php print $header_title ?></b></a>
                </td>
                <td style="text-align:right; vertical-align:middle; padding:0px;">
                    <div style="width:468px"></div>
                </td>
            </tr>
        </table>
        <br/>

        <hr/>
        <br/>
        <?php
            // Print any errors.

            if (isset($errors) && count($errors)) {
                foreach ($errors as $value) {
                    print "<span class=\"error_messages\"><b>".htmlentities($value)."</b></span><br/>";
                }
                print "<br/>";
            }

        ?>
        <form action="<?php print htmlspecialchars($_SERVER["PHP_SELF"]) ?>" method="post">
            <div id="lookup_form">
                <input type="text" name="domain" value="<?php print isset($_POST['domain']) ? htmlentities($_POST['domain']) : ''; ?>">
                <select name="extension">
                <?php
                    foreach ($extensions_array as $value) {
                        $selected =
                            (isset($_POST['extension']) && $_POST['extension'] == $value) || (!isset($_POST['extension']) && $value == $default_extension)
                                ? 'selected'
                                : '';
                        print "<option value=\"$value\" ${selected}>" . htmlentities($value) . "</option>\n";
                    }
                ?>
                </select>
                <input type="submit" value="whois lookup">
            </div>
        </form>
        <?php

            if (isset($domain_registered_message) && !empty($domain_registered_message)) {
                print "<br/>${domain_registered_message}<br/><br/>";
            }

            if (isset($response) && !empty($response)) {
                print "<div class=\"response_display\">Response from the WHOIS server ($whois_server):<br><br>". str_replace("\n", "<br/>", htmlentities($response)) . "</div>";
            }

            if ($_SERVER['REQUEST_METHOD'] == "GET") {
        ?>
            <br/>Enter a domain above to use our WHOIS information data lookup service to research the owner of a domain name or see the domain is available to register.  The whois lookup response is a public record that anyone can see.  The owner of a domain name may use a privacy service to hide their address and contact information. To you keep your name and address private be sure to choose the domain privacy option when <a href="http://www.kqzyfj.com/click-9079917-514796">purchasing your domain</a>. For your own personal financial safety and security we recommend NEVER using Godaddy for anything. WhoisInformation.NET has no control over the domain name ownership information displayed.
			<br/><br/><hr/><br/>
			<div id="other_link"><b>Other Tools</b></div>
			<br/>
			Your IP address is:<b> <? echo $_SERVER["REMOTE_ADDR"]; ?></b>
			<br/><br/>
			<b>Your UserAgent Information:</b>
			<br/>
			<div id="container"></div>
			<script>
var txt = "";
txt += "Browser CodeName: " + navigator.appCodeName + "<br/>";
txt += "Browser Name: " + navigator.appName + "<br/>";
txt += "Browser Version: " + navigator.appVersion + "<br/>";
txt += "Cookies Enabled: " + navigator.cookieEnabled + "<br/>";
txt += "Browser Language: " + navigator.language + "<br/>";
txt += "Platform: " + navigator.platform + "<br/>";
txt += "User-agent header: " + navigator.userAgent + "<br/>";

document.getElementById("container").innerHTML = txt;
</script>
<br/>Your UserAgent and IP address information are visible across the internet. Every website you visit is able to gather this information and companies use this information to track you. One of the best ways to maintain your privacy online is by using a VPN. Similar to a domain whois privacy service, a VPN can hide your IP address from trackers, criminals, and security vulnerabilities across the internet. We highly recommend using <a href="http://www.anrdoezrs.net/click-9079917-12956939">Nord VPN</a> to protect your identity online.
			
        <?php
            }
        ?>
        <br/>
        <br/>
       </div>
	   
	   <BR/>
	   
	       <div class="container">
        <table style="width:100%; border-collapse: collapse;">
            <tr>
                <td style="text-align:left; vertical-align:middle; padding:0px;">
                    <div id="other_link"><b>Our Friends</b></div>
                </td>
                <td style="text-align:right; vertical-align:middle; padding:0px;">
                    <div style="width:468px"></div>
                </td>
            </tr>
        </table>
		<br/>
		<hr/>
		<br/>
		<center>
			<a href="http://www.anrdoezrs.net/click-9079917-12814549" target="_top">
			<img src="http://www.lduhtrp.net/image-9079917-12814549" width="728" height="90" alt="" border="0"/></a>
			<br/>
			<a href="http://www.anrdoezrs.net/click-9079917-12956939" target="_top">Grab Special Deal</a> for a 2-Year VPN Plan.<img src="http://www.tqlkg.com/image-9079917-12956939" width="1" height="1" border="0"/>
			<br/><br/>
			<a href="http://www.anrdoezrs.net/click-9079917-12853401" target="_top">
			<img src="http://www.lduhtrp.net/image-9079917-12853401" width="728" height="90" alt="" border="0"/></a>
			<br/>
			<a href="http://www.tkqlhce.com/click-9079917-13548107" target="_top">Dedicated Servers, VPS Hosting, Wordpress and more! Liquid Web Managed Hosting Products page with 24/7 Support</a><img src="http://www.ftjcfx.com/image-9079917-13548107" width="1" height="1" border="0"/>
			
			
		<br/><br/>
			
		</center>
       </div>
	  <br/>
	   	       <div class="container">
      				Copyright &copy; 2019 whoisinformation.net | <a href="privacy.html">PRIVACY POLICY</a> | <a href="linktous.html">LINK TO US</a> | <a href="https://whois.icann.org/en/policies">ICANN WHOIS POLICY</a> | <a href="https://en.wikipedia.org/wiki/WHOIS">WHOIS Wikipedia</a>		
				</div>
	   
</body>
</html>
