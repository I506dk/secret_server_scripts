<#

Powershell script to automatically log into a given url using selenium

# Documentation/examples for the selenium powershell module
# https://github.com/adamdriscoll/selenium-powershell

# Example usage from the command line
# powershell.exe C:\path\to\script\.\web_login.ps1 -username myusername -password mypassword -webpage_url https://mypage.com/login -username_id signin-username -password_id signin-pasword -submit_id signin-button

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
Process Arguments: C:\path\to\script\.\web_login.ps1 -username $USERNAME -password $PASSWORD -webpage_url https://mypage.com/login -username_id signin-username -password_id signin-pasword -submit_id signin-button
Run Process as Secret Credentials: No
Load User Profile: No
Use Operating System Shell: No

Escape Character: `
Charactes to Escape: $&(){}<>\|;',
#########################################################

#>


# Set input parameters
param(
    # Username field
    [Parameter(Mandatory=$true,
    HelpMessage="The username to inject into the webpage.")]
    [string]$username,

    # Password field
    [Parameter(Mandatory=$true,
    HelpMessage="The password to inject into the webpage.")]
    [string]$password,

    # Webpage login url field
    [Parameter(Mandatory=$true,
    HelpMessage="The url of the webpage to log into.")]
    [string]$webpage_url,

    # Username field ID on the login webpage
    [Parameter(Mandatory=$true,
    HelpMessage="The url of the webpage to log into.")]
    [string]$username_id,

    # Password field ID on the login webpage
    [Parameter(Mandatory=$true,
    HelpMessage="The url of the webpage to log into.")]
    [string]$password_id,

    # Submit/enter button field ID on the login webpage
    [Parameter(Mandatory=$true,
    HelpMessage="The url of the webpage to log into.")]
    [string]$submit_id
)


######### Define hard coded cariables here #########
# Set the browser type
$browser = "chrome"
# Set the working path for the script to download files to and work out of
$working_directory = "C:\Program Files\WindowsPowerShell\Modules\Selenium\Chromedriver_Utilities"
####################################################


# Check if selenium exists. If not, install it.
if (Get-Module -ListAvailable -Name Selenium) {
    # Import the selenium module
    Import-Module Selenium
} else {
    # Install selenium
    Install-Module -Name Selenium -RequiredVersion 3.0.1 -Force

    # Import the selenium module
    Import-Module Selenium
}


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
    $registry_path = reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ /s /f \$FileName | findstr Default
    # regex to find the drive letter until $FileName
    if ($registry_path -match "[A-Z]\:.+$FileName") {
        return @{
            success = $true
            path = $Matches[0]
        }
         Write-Host "Found path in registry."
    }
    else {
        return @{
            success = $false
            path = ""
        }
    }
}


# Define a function to parse the chrome driver page,
# and download the correct driver for a given version of chrome
function Download-Driver {
    Param (
        [Parameter(Mandatory=$true)]$chrome_version
    )
    Write-Host "Downloading chrome driver executable..."

    # Modern browsers require TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

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
            Get-ChildItem $working_directory -Recurse | Remove-Item -Force -Recurse
        } else {
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
    $unzipped_path
}


# Initially try to launch chrome. 
try {
    # Remove any already running chrome driver processes
    purge_driver_process

    # Start chrome browser in incognito mode
    $driver = Start-SeChrome -Incognito

    # Sleep for 1 second
    Start-Sleep -Seconds 1

    # Navigate to the webpage login url
    Enter-SeUrl $webpage_url -Driver $driver

    # Sleep for 1 second
    Start-Sleep -Seconds 1

    # Find the username element id
    $username_element = Find-SeElement -Driver $driver -Id $username_id

    # Find the password element id
    $password_element = Find-SeElement -Driver $driver -Id $password_id

    # Find the submit button id
    $submit_element = Find-SeElement -Driver $driver -Id $submit_id

    # Send the username to the username field in the browser
    Send-SeKeys -Element $username_element -Keys $username

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
        $driver_path = Test-Path "C:\Program Files\WindowsPowerShell\Modules\Selenium"

        if ($driver_path -eq $true) {
            # Get selenium version since it appears in the file path
            $selenium_version = (Find-Module -Name Selenium).Version.ToString()

            # Set chrome driver path
            $driver_full_path = "C:\Program Files\WindowsPowerShell\Modules\Selenium\" + $selenium_version + "\assemblies\chromedriver.exe"

            # Download the respective version of the chrome driver
            $output_path = (Download-Driver $browser_version)
            $chrome_driver_path = Join-Path $output_path[-1] "\chromedriver.exe"

            # Check if a driver already exists or not
            if ((Test-Path $driver_full_path) -eq $true) {
                # Delete the old driver and replace it with the correct one
                Remove-Item $driver_full_path -Force
                #Rename-Item -Path $driver_full_path -NewName "chromedriver_older.exe"
                # Move the new driver to the assemblies folder
                Move-Item –Path $chrome_driver_path -Destination $driver_full_path

            } else {
                # Move the new driver to the assemblies folder
                Move-Item –Path $chrome_driver_path -Destination $driver_full_path
            }
        } else {
            Write-Host "Selenium not installed despite checks."
        }

        # Start chrome browser in incognito mode
        $driver = Start-SeChrome -Incognito

        # Sleep for 1 second
        Start-Sleep -Seconds 1

        # Navigate to the webpage login url
        Enter-SeUrl $webpage_url -Driver $driver

        # Sleep for 1 second
        Start-Sleep -Seconds 1

        # Find the username element id
        $username_element = Find-SeElement -Driver $driver -Id $username_id

        # Find the password element id
        $password_element = Find-SeElement -Driver $driver -Id $password_id

        # Find the submit button id
        $submit_element = Find-SeElement -Driver $driver -Id $submit_id

        # Send the username to the username field in the browser
        Send-SeKeys -Element $username_element -Keys $username

        # Send the password to the password field in the browser
        Send-SeKeys -Element $password_element -Keys $password

        # Send the command to click the submit or sign-in button
        Invoke-SeClick -Element $submit_element

    } else {
        Write-Host "Cannot find $broswer on this machine."
    }
}

### Cleanup ###
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
###############
