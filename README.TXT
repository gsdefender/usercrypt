Installation:

Please read carefully! This process is irreversible!

CURRENT USER BACKUP PROCEDURE:

1. Before the installation, open your phpMyAdmin from web hosting control panel

2. find and select table jos_users, then choose Export tab.

3. click Custom radiobutton (may not be available in lower version of phpMyadmin)

4. make sure the format is SQL, Structure & Data option is checked

5. click "Go" on very bottom


PLUGIN INSTALLATION:

1. Download usercrypt_UnzipFirst.zip and unzip it to some temporary folder

2. Open your administration back-end.

3. Click Extensions -> Install

4. Choose file usercrypt_database.zip from temporary folder, click "Upload File & Install"

5. Choose file usercrypt_user.zip from temporary folder, click "Upload File & Install"

6. Choose file usercrypt_authentication.zip from temporary folder, click "Upload File & Install"


PLUGIN ACTIVATION:

1. create a file on your local machine named for example: encryption_key.php - place there the content <?php YOUR_SPECIAL_KEY; ?>

   this is because the file encryption_key.php key will be interpreted as PHP code and will be not displayed to end user when accessed via browser

2. store the file into the root of your joomla installation using the FTP client

3. Open Extensions -> Plugin Manager, (to find latest plugins - click on ID on very right, will sort it by latest ones)

4. Choose UserCrypt - user encryption - Create User / Login / Logout

5. In field Filesystem path to security key type the value: key.php, set Enabled radio button to : Yes, then Save

6. Click on red icon "enable plugin" in row which contains name UserCrypt - user encrypt - Database Interceptor (the icon will change to green tick)

7. Click on red icon "enable plugin" in row which contains name UserCrypt - user encrypt - Authentication (the icon will change to green tick)


TEST:

1. Refresh phpMyAdmin jos_users table (Ctrl+R in your browser)

2. The data of this table should not contain any plain email addressess or usernames, but just numbers within range 0-9 and letters a-f


