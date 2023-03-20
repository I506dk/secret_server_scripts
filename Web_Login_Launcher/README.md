# Custom Web Login Launcher for Secret Server

![secret_server](https://user-images.githubusercontent.com/33561466/216741532-18d4c459-211e-484d-a69f-838d3ae1fee1.png)

#### A powershell script to automate the launch of a webpage and automatically log into it.

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Features
- Automatically download the latest chrome driver
- Install prerequisites like Selenium
- Automatically log into a webpage using secret credentials from Secret Server
- Kill any outstanding or existing chromedriver processes

## Dependencies
- [Selenium](https://github.com/adamdriscoll/selenium-powershell) - Browser automation
- [Chrome Driver](https://chromedriver.chromium.org/) - Web driver for automation and testing

## Usage
To run web_login.ps1 for the first time:
From command line:
```
powershell ./web_login.ps1
```
From powershell:
```
./web_login.ps1
```
This will configure install Selenium, and download the respective chrome driver.

Arguments can be passed to the script for automation (required for use as a launcher within Secret Server).

(***-username***) - the username used to log into the given webpage.

- Examples: ```powershell ./web_login.ps1 -username``` or ```./web_login.ps1 -username```

(***-password***)  - the password used to log into the given webpage.

- Examples: ```powershell ./web_login.ps1 -password``` or ```./web_login.ps1 -password```

(***-webpage_url***) - the url for the login webpage.

- Examples: ```powershell ./web_login.ps1 -webpage_url``` or ```./web_login.ps1 -webpage_url```

(***-username_id***) - the id of the username field on the given login webpage.

- Examples: ```powershell ./web_login.ps1 -username_id``` or ```./web_login.ps1 -username_id```

(***-password_id***) - the id of the password field on the given login webpage.

- Examples: ```powershell ./web_login.ps1 -password_id``` or ```./web_login.ps1 -password_id```

(***-submit_id***) - the id of the submit, sign-in, or login button on the given webpage.

- Examples: ```powershell ./web_login.ps1 -submit_id``` or ```./web_login.ps1 -submit_id```

Example run using arguments:
```
powershell C:\path\to\script\.\web_login.ps1 -username myusername -password mypassword -webpage_url https://mypage.com/login -username_id signin-username -password_id signin-pasword -submit_id signin-button
```
or
```
C:\path\to\script\.\web_login.ps1 -username myusername -password mypassword -webpage_url https://mypage.com/login -username_id signin-username -password_id signin-pasword -submit_id signin-button
```

## Configuration as a Custom Launcher
To configure this script as a launcher in Secret Server, navigate to "**Administration -> Secret Templates -> Launchers**". Create a new launcher by clicking the "**Create**" button in the top right.

#### General Settings
- Launcher Type - **Process**
- Launcher Name - **Your Web Launcher Name**
- Active - **Yes**
- Launcher Image - ***Optional***
- Wrap Custom Parameters with Quotation Marks - **No**
- Track Multiple Windows - **Yes**
- Record Additional Processes - **< None >**
- Use SSH Tunneling with SSH Proxy - **No**

#### Windows Settings
- Process Name - **powershell.exe**
- Process Arguments - **-NoExit "C:\path\to\script\.\web_login.ps1" -username $USERNAME -password $PASSWORD -webpage_url "https://your-page.com/login" -username_id "username-element-id" -password_id "password-element-id" -submit_id "submit-button-element-id"**
- Run Process as Secret Credentials - **No**
- Load User Profile - **No**
- Use Operating System Shell - **No**
##### Advanced
- Escape Character - **`**
- Characters to Escape - **$&(){}<>\|;',**

NOTE - The backtick (`) character is the escape character for powershell. The hyphen character (-) cannot be used or escaped as it is used to indicate an argument in powershell.

## Adding the launcher to a Secret Template
Once the launcher has been created, it can be added to a Secret Template by navigating to "**Administration -> Secret Templates -> Your Template Name -> Mapping**". Add the launcher to the template by clicking the "**Add Mapping**" button in the top right. Select the launcher that was just created and map "**Username**" and "**Password**" to their respective fields. The "**Domain**" field can be left mapped to "**<blank>**".

