<#

Powershell script to automatically log into a given url using selenium

# Documentation/examples for the selenium powershell module
# https://github.com/adamdriscoll/selenium-powershell

# Example usage from the command line
# powershell.exe C:\path\to\script\.\web_login.ps1 -username myname -password mypasword -domain my.domain -webpage_url "https://mypage.com/" -username_id "signin-username" -password_id "signin-password" -submit_id "signin-button"

# Password field may contain characters that need to be escaped using a backtick `
# Characters to escape: $&(){}<>\|;',


### Example launcher created for use in secret server ###
Launcher Type: Process
Launcher Name: "Your launcher name"
Active: Yes

Wrap custom parameters with quotation marks: No
Track Multiple Windows: Yes
Record Additional Processes: < None >
Use SSH Tunneling with SSH Proxy: No

Process Name: powershell.exe
Process Arguments: C:\path\to\script\.\web_login.ps1 -username '$USERNAME' -password '$PASSWORD' -domain '$DOMAIN' -webpage_url "https://mypage.com/" -username_id "signin-username" -password_id "signin-password" -submit_id "signin-button"
Run Process as Secret Credentials: No
Load User Profile: No
Use Operating System Shell: No

Escape Character: `
Charactes to Escape: $&(){}<>\|;',
#########################################################

#>

# Set input parameters
param(
    # Username field (Required)
    [Parameter(Mandatory=$true,
    HelpMessage="The username to inject into the webpage.")]
    [string]$username,

    # Password field (Required)
    [Parameter(Mandatory=$true,
    HelpMessage="The password to inject into the webpage.")]
    [string]$password,
	
	# Domain field (Required)
	[Parameter(Mandatory=$true,
    HelpMessage="The domain of the user account being used to login.")]
    [string]$domain,

	# Mode argument
	# if the domain is supplied this determines whether the username should be formatted differently
	# For example domain\username or username@domain instead of just the username
	# Options for the mode argument should be domain, email, or username
	[Parameter(Mandatory=$false,
    HelpMessage="The mode that defines the formatting of the username. Examples: domain\username or username@domain")]
    [string]$mode,

    # Webpage login url field (Required)
    [Parameter(Mandatory=$true,
    HelpMessage="The url of the webpage to log into.")]
    [string]$webpage_url,

    # Username field ID on the login webpage (Required)
    [Parameter(Mandatory=$true,
    HelpMessage="The url of the webpage to log into.")]
    [string]$username_id,

    # Password field ID on the login webpage (Required)
    [Parameter(Mandatory=$true,
    HelpMessage="The url of the webpage to log into.")]
    [string]$password_id,

    # Submit/enter button field ID on the login webpage (Required)
    [Parameter(Mandatory=$true,
    HelpMessage="The url of the webpage to log into.")]
    [string]$submit_id
)

# Modern browsers require TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Get the current execution policy for the given user and process
$execution_policy_user = Get-ExecutionPolicy -Scope CurrentUser
$execution_policy_process = Get-ExecutionPolicy -Scope Process

# Set the execution policy to bypass for the current user and process
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
Set-ExecutionPolicy Bypass -Scope Process -Force

# Check if selenium exists. If not, install it.
if (Get-Module -ListAvailable -Name Selenium) {
    # Import the selenium module
    Import-Module Selenium
	Write-Host "Imported Selenium"
} else {
	Write-Host "Installing Selenium..."
    # Install selenium
    Install-Module -Name Selenium -RequiredVersion 3.0.1 -Force -Scope CurrentUser

    # Import the selenium module
    Import-Module Selenium
}

# Get the install path of selenium
$selenium_path = (Get-Module -ListAvailable Selenium).path
$selenium_path = $selenium_path.replace("Selenium.psd1", "")

####################################################
######### Define hard coded variables here #########
# Set the browser type
$browser = "chrome"
# Set the working path for the script to download files to and work out of
$working_directory = $selenium_path + "Chromedriver_Utilities"

# Element IDs for the advanced/continue buttons on chrome that appear when https is not being used,
# Or when the cert provided by the site isn't trusted.
# These IDs are specific to chrome
$advanced_button_id = "details-button"
$proceed_button_id = "proceed-link"

# Set the default wait time in between items (In seconds)
$default_wait = 1

####################################################
####################################################


# Define a function to kill the chrome driver process if found
function purge_driver_process {
    $driver_process = Get-Process "chromedriver" -ErrorAction SilentlyContinue
    # If any processes were returned, stop them
    if ($driver_process) {
        Write-Host "Killing chromedriver.exe process..."
        $driver_process | Stop-Process -Force
    }
    # Remove the variable afterwards to avoid lingering values
    Remove-Variable driver_process
}


# Define function to dynamically find the location of an application by looking for it in the registry
function find_application_path {
    param (
        [string]$FileName
    )
    Write-host "Searching for executable path in the registry..."
    # Search the HKLM registry for the application
    $registry_path = reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths" /s /f \$FileName | findstr Default
    # regex to find the drive letter until $FileName
    if ($registry_path -match "[A-Z]\:.+$FileName") {
		Write-Host "Found $FileName path in registry."
        return @{
            success = $true
            path = $Matches[0]
        }
    }
    else {
		Write-Host "Could not find path for $FileName"
        return @{
            success = $false
            path = ""
        }
    }
}


# Define a function to parse the chrome driver page,
# and download the correct driver for a given version of chrome
function download_Driver {
    Param (
        [Parameter(Mandatory=$true)]$chrome_version
    )
    Write-Host "Downloading chrome driver executable..."

    # Get all the links from the chromedriver site
    $driver_links = (Invoke-WebRequest "https://chromedriver.chromium.org/downloads" -UseBasicParsing).Links

    # Get the major.minor.patch version from the browser version paramter passed to this function
    $version = $chrome_version.Substring(0, $chrome_version.LastIndexOf('.'))

    # For each of the links returned, look for any that contain a similar version number
    # Break out of the loop on the first similar link found (First is the latest)
    foreach ($link in $driver_links) {
        if ($link.Href -like "https://chromedriver.storage.googleapis.com/index.html?path=$version*") {
            # Get the version of the chromedriver
            $driver_version = ($link.Href).Replace("https://chromedriver.storage.googleapis.com/index.html?path=", "")
            $driver_version = $driver_version.Replace("/", "")
            # Create download url based on the chromedriver version
            $driver_download_url = "https://chromedriver.storage.googleapis.com/$driver_version/chromedriver_win32.zip"
            break
        }
    }

    # If there is a driver download url created, download and extract the chromedriver
    if ($driver_download_url) {
        # Make sure working directory exists
        $working_directory_check = Test-Path $working_directory
        # If path exists, delete anything in it. Otherwise create it.
        if ($working_directory_check -eq $true) {
			Write-Host "Working directory exists. Continuing..."
            Get-ChildItem $working_directory -Recurse | Remove-Item -Force -Recurse
        } else {
			Write-Host "Working directory doesn't exist. Creating..."
            New-Item -Path $working_directory -ItemType Directory
        }

        # Set temporary download path
        $download_path = Join-Path $working_directory (Split-Path $driver_download_url -Leaf)

        # Download the chrome driver zip file
        $driver_download = Invoke-WebRequest $driver_download_url -OutFile $download_path

        # Unzip the archive
        $unzipped_path = $download_path.Replace(".zip", "")
        Expand-Archive $download_path -DestinationPath $unzipped_path -Force

        # Delete the zip file
        Remove-Item $download_path
    }
    # Return the unzipped folder path
	return @{
		success = $true
		path = $unzipped_path
	}
}


# Define a function to change the username format that is passed to the webpage
function format_username {
	param (
        [string]$username_mode,
		[string]$passed_username,
		[string]$passed_domain
    )
	# If the mode contains domain, assume that the username should be formatted
	# domain\username
    Write-Host "formatting username"
	if ($username_mode -contains "domain") {
		$formatted_username = ($passed_domain.Split("."))[0] + "\" + $passed_username
	# If the mode contains email, assume that the username should be formatted
	# username@domain
	} elseif ($username_mode -contains "email"){
		$formatted_username = $passed_username + "@" + $passed_domain
	# Assume anything else just needs the base username
	} else {
		$formatted_username = $passed_username
	}
	# Return the newly formatted username
	return @{
		success = $true
		name = $formatted_username
	}
	
}


# Initially try to launch chrome. 
try {
    # Remove any already running chrome driver processes
    purge_driver_process

    # Start chrome browser in incognito mode
    $driver = Start-SeChrome -Incognito

	# Try to navigate to login url, if SSL errors exist, bypass them
	try {
		# Sleep for default count
		Start-Sleep -Seconds $default_wait
		
		# Navigate to the webpage login url
		Enter-SeUrl $webpage_url -Driver $driver
	} catch {
		# Sleep for default count
		Start-Sleep -Seconds $default_wait
		
		# Click the advanced/error details button
		$advanced_button = Find-SeElement -Driver $driver -Id $advanced_button_id
		Invoke-SeClick -Element $advanced_button
		
		# Click the proceed to url button
		$proceed_button = Find-SeElement -Driver $driver -Id $proceed_button_id
		Invoke-SeClick -Element $proceed_button
	} finally {
		# Sleep for default count
		Start-Sleep -Seconds $default_wait
		
		# Navigate to the webpage login url
		Enter-SeUrl $webpage_url -Driver $driver
    }

    # Sleep for default count
    Start-Sleep -Seconds $default_wait

    # Find the username element id
    $username_element = Find-SeElement -Driver $driver -Id $username_id

    # Find the password element id
    $password_element = Find-SeElement -Driver $driver -Id $password_id

    # Find the submit button id
    $submit_element = Find-SeElement -Driver $driver -Id $submit_id

    # If the mode is set, format the username respectively
    if ($mode) {
        # Get the newly formatted username
        $formatted_username = (format_username -username_mode $mode -passed_username $username -passed_domain $domain).name

        # Send the username to the username field in the browser
        Send-SeKeys -Element $username_element -Keys $formatted_username
    } else {
        # Send the username to the username field in the browser
        Send-SeKeys -Element $username_element -Keys $username
    }

    # Send the password to the password field in the browser
    Send-SeKeys -Element $password_element -Keys $password

    # Send the command to click the submit or sign-in button
    Invoke-SeClick -Element $submit_element

} catch {
    # If the driver started and failed, make sure the process no longer exists.
    # This could be from wrong driver version, etc.
    # Remove any already running chrome driver processes
    purge_driver_process

    # Set browser executable name
    $browser_executable = $browser + ".exe"

    # Get browser install path
    $browser_check = find_application_path $browser_executable

    # Check if browser was found on the current machine
    if ($browser_check.success -eq $true) {
        # Get the executable path
        $browser_path = $browser_check.path

        ##### CHROME SPECIFIC #####
        # Get current browser version using the executable path
        $browser_version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($browser_path).ProductVersion

        # Check to see if the chrome driver already exists.
        # If so, make sure it is the correct version.
        $driver_path = Test-Path $selenium_path

        if ($driver_path -eq $true) {
            # Get selenium version since it appears in the file path
            $selenium_version = (Find-Module -Name Selenium).Version.ToString()

            # Set chrome driver path
            $driver_full_path = $selenium_path + "assemblies\chromedriver.exe"

            # Download the respective version of the chrome driver
            $output_path = (download_driver $browser_version).path
            $chrome_driver_path = Join-Path $output_path "\chromedriver.exe"
			
            # Check if a driver already exists or not
			$existing_driver = Test-Path $driver_full_path
            if ($existing_driver -eq $true) {
                # Delete the old driver and replace it with the correct one
                Remove-Item $driver_full_path -Force
                # Move the new driver to the assemblies folder
                $chrome_driver_path | Move-Item -Destination $driver_full_path -Force
            } else {
                # Move the new driver to the assemblies folder
                $chrome_driver_path | Move-Item -Destination $driver_full_path -Force
            }
        } else {
            Write-Host "Selenium not installed despite checks."
        }

		# Start chrome browser in incognito mode
		$driver = Start-SeChrome -Incognito

		# Try to navigate to login url, if SSL errors exist, bypass them
		try {
			# Sleep for default count
			Start-Sleep -Seconds $default_wait
			
			# Navigate to the webpage login url
			Enter-SeUrl $webpage_url -Driver $driver
			
		} finally {
			# Sleep for default count
			Start-Sleep -Seconds $default_wait
			
			# Click the advanced/error details button
			$advanced_button = Find-SeElement -Driver $driver -Id $advanced_button_id
			Invoke-SeClick -Element $advanced_button
			
			# Click the proceed to url button
			$proceed_button = Find-SeElement -Driver $driver -Id $proceed_button_id
			Invoke-SeClick -Element $proceed_button
		}

		# Sleep for default count
		Start-Sleep -Seconds $default_wait

		# Find the username element id
		$username_element = Find-SeElement -Driver $driver -Id $username_id

		# Find the password element id
		$password_element = Find-SeElement -Driver $driver -Id $password_id

		# Find the submit button id
		$submit_element = Find-SeElement -Driver $driver -Id $submit_id

        # If the mode is set, format the username respectively
        if ($mode) {
            # Get the newly formatted username
            $formatted_username = (format_username -username_mode $mode -passed_username $username -passed_domain $domain).name

            # Send the username to the username field in the browser
            Send-SeKeys -Element $username_element -Keys $formatted_username
        } else {
            # Send the username to the username field in the browser
            Send-SeKeys -Element $username_element -Keys $username
        }

		# Send the password to the password field in the browser
		Send-SeKeys -Element $password_element -Keys $password

		# Send the command to click the submit or sign-in button
		Invoke-SeClick -Element $submit_element

    } else {
        Write-Host "Cannot find $broswer on this machine."
    }
}

##### Cleanup #####
# Sleep for default count
Start-Sleep -Seconds $default_wait

Write-Host "Cleaning up..."
# Stop the chrome driver process
purge_driver_process
# Delete any temporary files
$working_directory_check = Test-Path $working_directory
if ($working_directory_check -eq $true) {
    Get-ChildItem $working_directory -Recurse | Remove-Item -Force -Recurse
    # Delete the working directory
    Remove-Item $working_directory -Force
}
# Reset the execution policy
Set-ExecutionPolicy $execution_policy_user -Scope CurrentUser -Force
Set-ExecutionPolicy $execution_policy_process -Scope Process -Force
###################
