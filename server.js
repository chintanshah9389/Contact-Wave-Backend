require('dotenv').config(); // Load environment variables from .env file

const express = require('express');
const bodyParser = require('body-parser');
const { google } = require('googleapis');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const twilio = require('twilio');
const { TelegramClient, StringSession, Api } = require('telegram');

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(
    cors({
        origin: 'http://localhost:3000',
        credentials: true,
    })
);
app.use(cookieParser());

// Environment Variables
const REGISTRATION_SPREADSHEET_ID = process.env.REGISTRATION_SPREADSHEET_ID;
const LOGIN_SPREADSHEET_ID = process.env.LOGIN_SPREADSHEET_ID;
const SECRET_KEY = process.env.SECRET_KEY;
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;
const TELEGRAM_API_ID = process.env.TELEGRAM_API_ID;
const TELEGRAM_API_HASH = process.env.TELEGRAM_API_HASH;
const TELEGRAM_SESSION_STRING = process.env.TELEGRAM_SESSION_STRING;
const CREDENTIALS = require('./credentials.json'); // Path to your credentials.json file



const auth = new google.auth.GoogleAuth({
    credentials: CREDENTIALS,
    scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});


const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    console.log('Token received in middleware:', token); // Log the token for debugging

    if (!token) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).json({ success: false, message: 'Invalid token' });
        }
        req.user = decoded;
        next();
    });
};

// Add this route to check token expiration
app.get('/check-token-expiration', verifyToken, (req, res) => {
    const token = req.cookies.token;

    try {
        // Verify the token and decode it
        const decodedToken = jwt.verify(token, SECRET_KEY);
        const expirationTime = decodedToken.exp * 1000; // Convert to milliseconds
        const currentTime = Date.now();
        const timeLeft = expirationTime - currentTime;

        // Return the time left in JSON format
        res.status(200).json({ timeLeft });
    } catch (error) {
        // Return a JSON error response
        res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
});

// Handle Registration
app.post('/register', async (req, res) => {
    const { firstName, middleName, surname, mobile, email, gender, password } = req.body;

    const sheets = google.sheets({ version: 'v4', auth: await auth.getClient() });

    try {
        const existingData = await sheets.spreadsheets.values.get({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Sheet1!A:G',
        });

        const uniqueId = existingData.data.values.length;

        await sheets.spreadsheets.values.append({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Sheet1!A:H',
            valueInputOption: 'USER_ENTERED',
            resource: {
                values: [[firstName, middleName, surname, mobile, email, gender, password, uniqueId]],
            },
        });

        res.status(200).send('Registration successful');
    } catch (err) {
        console.error('Error writing to registration sheet:', err);
        res.status(500).send('Error saving registration data');
    }
});

// Handle Login
app.post('/login', async (req, res) => {
    const { emailOrMobile, password } = req.body;
    const sheets = google.sheets({ version: 'v4', auth: await auth.getClient() });

    try {
        const response = await sheets.spreadsheets.values.get({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Sheet1!A:G',
        });

        const rows = response.data.values;

        if (!rows || rows.length === 0) {
            return res.status(404).json({ success: false, message: 'No data found' });
        }

        const user = rows.find(
            (row) =>
                row[3] === emailOrMobile || // Match Mobile
                row[4]?.toLowerCase() === emailOrMobile.toLowerCase() // Match Email
        );

        if (user) {
            if (user[6] === password) {
                // Generate JWT
                const token = jwt.sign({ email: user[4] }, SECRET_KEY, { expiresIn: '1h' });

                // Set JWT in an HTTP-only cookie
                res.cookie('token', token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
                    sameSite: 'strict', // Prevent CSRF attacks
                    maxAge: 3600000, // 1 hour
                });

                console.log("Created On login: ", token);

                return res.status(200).json({ success: true, message: 'Login successful' });
            } else {
                return res.status(401).json({ success: false, message: 'Incorrect password' });
            }
        } else {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
    } catch (error) {
        console.error('Error validating login:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Handle Logout
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.status(200).json({ success: true, message: 'Logout successful' });
});

// Fetch User Data (Protected Route)
app.get('/fetch-user', verifyToken, async (req, res) => {
    const { email } = req.user; // Get email from JWT payload

    const sheets = google.sheets({ version: 'v4', auth: await auth.getClient() });

    try {
        const response = await sheets.spreadsheets.values.get({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Sheet1!A:K',
        });

        const rows = response.data.values;
        if (!rows || rows.length === 0) {
            return res.status(404).send('No data found in the spreadsheet.');
        }

        // Find the user with the matching email
        const headers = rows[0]; // First row contains headers
        const userData = rows.slice(1).find((row) => row[4] === email); // Assuming email is in the 5th column (index 4)

        if (!userData) {
            return res.status(404).send('User not found.');
        }

        // Map headers to user data
        const user = {
            firstName: userData[0],
            middleName: userData[1],
            surname: userData[2],
            mobile: userData[3],
            email: userData[4],
            gender: userData[5],
            profilePic: null, // Add profile picture URL if available
        };

        res.status(200).json(user); // Return the user's data as JSON
    } catch (err) {
        console.error('Error fetching data from spreadsheet:', err.message);
        res.status(500).send('Error fetching data from the spreadsheet');
    }
});

app.get('/fetch-registrations', async (req, res) => {
    const sheets = google.sheets({ version: 'v4', auth: await auth.getClient() });

    try {
        const response = await sheets.spreadsheets.values.get({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Sheet1!A:K',
        });

        const rows = response.data.values;
        if (!rows || rows.length === 0) {
            return res.status(404).send('No data found in the spreadsheet.');
        }

        res.status(200).json(rows); // Return all rows as JSON
    } catch (err) {
        console.error('Error fetching data from spreadsheet:', err.message);
        res.status(500).send('Error fetching data from the spreadsheet');
    }
});

app.post('/edit-profile', verifyToken, async (req, res) => {
    const { firstName, middleName, surname, mobile, email, gender } = req.body;
    const { email: userEmail } = req.user; // Get email from JWT payload

    const sheets = google.sheets({ version: 'v4', auth: await auth.getClient() });

    try {
        // Fetch the current data from the spreadsheet
        const response = await sheets.spreadsheets.values.get({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Sheet1!A:K',
        });

        const rows = response.data.values;
        if (!rows || rows.length === 0) {
            return res.status(404).send('No data found in the spreadsheet.');
        }

        // Find the user with the matching email
        const userRowIndex = rows.slice(1).findIndex((row) => row[4] === userEmail) + 1; // +1 to account for header row

        if (userRowIndex === -1) {
            return res.status(404).send('User not found.');
        }

        // Update the user's details in the spreadsheet
        const updateRange = `Sheet1!A${userRowIndex + 1}:G${userRowIndex + 1}`; // Adjust for 1-based index in Sheets API
        await sheets.spreadsheets.values.update({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: updateRange,
            valueInputOption: 'USER_ENTERED',
            resource: {
                values: [[firstName, middleName, surname, mobile, email, gender, rows[userRowIndex][6]]], // Keep the password unchanged
            },
        });

        res.status(200).json({ success: true, message: 'Profile updated successfully' });
    } catch (err) {
        console.error('Error updating profile:', err.message);
        res.status(500).send('Error updating profile');
    }
});

// Handle Edit Row in Table
app.post('/edit-row', async (req, res) => {
    const { uniqueId, firstName, middleName, surname, mobile, email, gender } = req.body;

    const sheets = google.sheets({ version: 'v4', auth: await auth.getClient() });

    try {
        // Fetch the current data from the spreadsheet
        const response = await sheets.spreadsheets.values.get({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Sheet1!A:K',
        });

        const rows = response.data.values;
        if (!rows || rows.length === 0) {
            return res.status(404).send('No data found in the spreadsheet.');
        }

        // Find the row index of the user with the matching uniqueId
        const userRowIndex = rows.findIndex((row) => row[7] === uniqueId.toString());

        if (userRowIndex === -1) {
            return res.status(404).send('User not found.');
        }

        // Update the user's details in the spreadsheet
        const updateRange = `Sheet1!A${userRowIndex + 1}:G${userRowIndex + 1}`; // Adjust for 1-based index in Sheets API
        await sheets.spreadsheets.values.update({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: updateRange,
            valueInputOption: 'USER_ENTERED',
            resource: {
                values: [[firstName, middleName, surname, mobile, email, gender, rows[userRowIndex][6]]], // Keep the password unchanged
            },
        });

        res.status(200).json({ success: true, message: 'Row updated successfully' });
    } catch (err) {
        console.error('Error updating row:', err.message);
        res.status(500).send('Error updating row');
    }
});

app.delete('/delete-user', verifyToken, async (req, res) => {
    const { uniqueId } = req.body;

    const sheets = google.sheets({ version: 'v4', auth: await auth.getClient() });

    try {
        // Fetch the current data from the main spreadsheet
        const mainSheetResponse = await sheets.spreadsheets.values.get({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Sheet1!A:K',
        });

        const mainSheetRows = mainSheetResponse.data.values;
        if (!mainSheetRows || mainSheetRows.length === 0) {
            return res.status(404).send('No data found in the main spreadsheet.');
        }

        // Find the row index of the user with the matching uniqueId in the main sheet
        const userRowIndex = mainSheetRows.findIndex((row) => row[7] === uniqueId.toString());

        if (userRowIndex === -1) {
            return res.status(404).send('User not found in the main sheet.');
        }

        // Delete the row from the main spreadsheet
        await sheets.spreadsheets.values.clear({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: `Sheet1!A${userRowIndex + 1}:K${userRowIndex + 1}`, // Adjust for 1-based index in Sheets API
        });

        // Fetch the current data from the group sheet
        const groupSheetResponse = await sheets.spreadsheets.values.get({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Group!A:E', // Adjust the range based on your group sheet
        });

        const groupSheetRows = groupSheetResponse.data.values;
        if (!groupSheetRows || groupSheetRows.length === 0) {
            return res.status(404).send('No data found in the group sheet.');
        }

        // Update each group to remove the deleted user
        for (let i = 1; i < groupSheetRows.length; i++) { // Start from 1 to skip header
            const groupMembers = groupSheetRows[i][2].split(','); // Assuming group members are in column C
            const updatedMembers = groupMembers.filter(member => member.trim() !== uniqueId.toString()).join(',');

            if (updatedMembers !== groupSheetRows[i][2]) {
                // Update the group members in the group sheet
                await sheets.spreadsheets.values.update({
                    spreadsheetId: REGISTRATION_SPREADSHEET_ID,
                    range: `Group!C${i + 1}`, // Adjust for 1-based index in Sheets API
                    valueInputOption: 'RAW',
                    resource: {
                        values: [[updatedMembers]],
                    },
                });
            }
        }

        res.status(200).json({ success: true, message: 'User deleted successfully and removed from all groups.' });
    } catch (err) {
        console.error('Error deleting user:', err.message);
        res.status(500).send('Error deleting user');
    }
});

app.post('/create-group', async (req, res) => {
    const { groupName, description, selectedFields } = req.body;

    if (!groupName || !selectedFields || selectedFields.length === 0) {
        return res.status(400).json({ message: 'Group name and selected fields are required.' });
    }

    const sheets = google.sheets({ version: 'v4', auth: await auth.getClient() });

    try {
        // Fetch the current data from the main sheet (Sheet1)
        const sheetResponse = await sheets.spreadsheets.values.get({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Sheet1!A:Z', // Adjust range to include all the registration data
        });

        const rows = sheetResponse.data.values;
        if (!rows || rows.length === 0) {
            console.log('No data found in the sheet.');
            return res.status(404).json({ message: 'No data found in the sheet.' });
        }

        // Generate a new Group ID (for example, a random number for simplicity)
        const groupId = Math.floor(Math.random() * 10000); // You can implement any logic for unique Group ID generation

        // Create a list of unique IDs for the group members
        const groupMembers = selectedFields.map(field => field.uniqueId).join(','); // Only store unique IDs, not passwords

        // Add the group name and members to the "Group" sheet (Sheet2)
        await sheets.spreadsheets.values.append({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Group!A:D', // Assuming columns A, B, C, D are for Group ID, Group Name, Description, and Members
            valueInputOption: 'USER_ENTERED',
            resource: {
                values: [[groupId, groupName, groupMembers, description]], // Add group details to the sheet
            },
        });

        // Update the Group Name and Group ID columns for each user in the "Sheet1" (Registration Sheet)
        for (let field of selectedFields) {
            // Find the user in the registration sheet by matching their unique ID
            const userRowIndex = rows.findIndex((row) => row[7] === field.uniqueId.toString());
        
            if (userRowIndex !== -1) {
                // Update the Group ID column (assuming column 9, index 8) and Group Name column (assuming column 10, index 9)
                const updateRange = `Sheet1!I${userRowIndex + 1}:J${userRowIndex + 1}`; // Adjust for 1-based index in Sheets API
                let currentGroupIds = rows[userRowIndex][8]; // Group ID column
                let currentGroupNames = rows[userRowIndex][9]; // Group Name column
        
                // Ensure the Group ID and Group Name are stored as strings, and avoid appending duplicates
                if (currentGroupIds) {
                    currentGroupIds = currentGroupIds.split(',');
                    if (!currentGroupIds.includes(groupId.toString())) {
                        currentGroupIds.push(groupId);
                    }
                } else {
                    currentGroupIds = [groupId];
                }

                if (currentGroupNames) {
                    currentGroupNames = currentGroupNames.split(',');
                    if (!currentGroupNames.includes(groupName)) {
                        currentGroupNames.push(groupName);
                    }
                } else {
                    currentGroupNames = [groupName];
                }

                // Update the user's Group ID and Group Name columns in Sheet1
                await sheets.spreadsheets.values.update({
                    spreadsheetId: REGISTRATION_SPREADSHEET_ID,
                    range: updateRange,
                    valueInputOption: 'USER_ENTERED',
                    resource: {
                        values: [[currentGroupIds.join(','), currentGroupNames.join(',')]], // Store as comma-separated values
                    },
                });
            }
        }

        res.status(200).json({
            message: `Group "${groupName}" created successfully with ID ${groupId}`,
            groupId: groupId, // Include the new group ID in the response for frontend
        });
    } catch (error) {
        console.error('Error creating group:', error.message);
        res.status(500).json({ message: 'Failed to create the group.' });
    }
});

app.get('/fetch-groups', async (req, res) => {
    const sheets = google.sheets({ version: 'v4', auth: await auth.getClient() });
    const sheetResponse = await sheets.spreadsheets.values.get({
        spreadsheetId: REGISTRATION_SPREADSHEET_ID,
        range: 'Group!A:C',
    });

    const rows = sheetResponse.data.values;
    if (!rows || rows.length === 0) {
        return res.status(404).json([]);
    }

    const groups = rows.slice(1).map(row => ({
        groupId: row[0],
        groupName: row[1],
    }));

    res.json({ groups }); // Ensure the response is an object with a `groups` key
});

app.get('/fetch-group-users', async (req, res) => {
    const { groupName } = req.query;
    console.log('Received groupName:', groupName);

    const sheets = google.sheets({ version: 'v4', auth: await auth.getClient() });
    const sheetResponse = await sheets.spreadsheets.values.get({
        spreadsheetId: REGISTRATION_SPREADSHEET_ID,
        range: 'Sheet1!A:Z',
    });

    const rows = sheetResponse.data.values;
    if (!rows || rows.length === 0) {
        return res.status(404).json({ users: [] });
    }

    const groupColumnIndex = 9; // Group Name is at index 9
    const users = rows.slice(1).filter(row => row[groupColumnIndex] && row[groupColumnIndex].split(',').includes(groupName));

    // Return all columns except Unique ID (index 7), Group ID (index 8), and Group Name (index 9)
    const formattedUsers = users.map(user => ({
        name: user[0], // First Name
        middleName: user[1], // Middle Name
        surname: user[2], // Surname
        mobile: user[3], // Mobile No
        email: user[4], // Email Address
        gender: user[5], // Gender
        password: user[6], // Password
        groupName: user[9]
    }));

    console.log('Formatted Users:', formattedUsers);
    res.json({ users: formattedUsers });
});

// Combine Groups
app.post('/combine-groups', async (req, res) => {
    const { groupNames, newGroupName, description } = req.body;

    const sheets = google.sheets({ version: 'v4', auth: await auth.getClient() });

    try {
        // Fetch all groups
        const groupResponse = await sheets.spreadsheets.values.get({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Group!A:D',
        });

        const groupRows = groupResponse.data.values;
        if (!groupRows || groupRows.length === 0) {
            return res.status(404).send('No groups found.');
        }

        // Fetch all users
        const userResponse = await sheets.spreadsheets.values.get({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Sheet1!A:K',
        });

        const userRows = userResponse.data.values;
        if (!userRows || userRows.length === 0) {
            return res.status(404).send('No users found.');
        }

        // Find users in the selected groups
        const selectedUsers = [];
        groupRows.slice(1).forEach((row) => {
            if (groupNames.includes(row[1])) {
                const userIds = row[2].split(',');
                userIds.forEach((id) => {
                    const user = userRows.find((userRow) => userRow[7] === id);
                    if (user && !selectedUsers.includes(user)) {
                        selectedUsers.push(user);
                    }
                });
            }
        });

        // Create a new group with the combined users
        const groupId = Math.floor(Math.random() * 10000); // Generate a unique group ID
        const groupMembers = selectedUsers.map((user) => user[7]).join(',');

        // Append the new group to the Group sheet
        await sheets.spreadsheets.values.append({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Group!A:D',
            valueInputOption: 'USER_ENTERED',
            resource: {
                values: [[groupId, newGroupName, groupMembers, description]],
            },
        });

        // Update the Sheet1 sheet with the new group for each user
        for (const user of selectedUsers) {
            const userGroups = user[9] ? user[9].split(',') : [];
            if (!userGroups.includes(newGroupName)) {
                userGroups.push(newGroupName);
                user[9] = userGroups.join(',');

                // Update the user row in Sheet1
                const userRowIndex = userRows.findIndex((row) => row[7] === user[7]);
                await sheets.spreadsheets.values.update({
                    spreadsheetId: REGISTRATION_SPREADSHEET_ID,
                    range: `Sheet1!A${userRowIndex + 1}:K${userRowIndex + 1}`,
                    valueInputOption: 'USER_ENTERED',
                    resource: {
                        values: [user],
                    },
                });
            }
        }

        res.status(200).json({ success: true, message: 'Groups combined successfully' });
    } catch (err) {
        console.error('Error combining groups:', err.message);
        res.status(500).send('Error combining groups');
    }
});

// Add Users to Existing Groups
// Add Users to Existing Groups
app.post('/add-to-existing-groups', async (req, res) => {
    const { groupNames, selectedFields } = req.body;

    const sheets = google.sheets({ version: 'v4', auth: await auth.getClient() });

    try {
        // Fetch all groups
        const groupResponse = await sheets.spreadsheets.values.get({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Group!A:D',
        });

        const groupRows = groupResponse.data.values;
        if (!groupRows || groupRows.length === 0) {
            return res.status(404).send('No groups found.');
        }

        // Fetch all users
        const userResponse = await sheets.spreadsheets.values.get({
            spreadsheetId: REGISTRATION_SPREADSHEET_ID,
            range: 'Sheet1!A:K',
        });

        const userRows = userResponse.data.values;
        if (!userRows || userRows.length === 0) {
            return res.status(404).send('No users found.');
        }

        // Update each selected group with the new users
        for (const groupName of groupNames) {
            const groupRowIndex = groupRows.findIndex((row) => row[1] === groupName);
            if (groupRowIndex !== -1) {
                const groupRow = groupRows[groupRowIndex];
                const existingMembers = groupRow[2].split(',');
                const newMembers = selectedFields.map((field) => field.uniqueId);

                // Combine existing and new members, ensuring no duplicates
                const updatedMembers = [...new Set([...existingMembers, ...newMembers])].join(',');

                // Update the group in the Google Sheet
                await sheets.spreadsheets.values.update({
                    spreadsheetId: REGISTRATION_SPREADSHEET_ID,
                    range: `Group!C${groupRowIndex + 1}`,
                    valueInputOption: 'USER_ENTERED',
                    resource: {
                        values: [[updatedMembers]],
                    },
                });
            }
        }

        // Update Sheet1 with the new group information for each user
        for (const user of selectedFields) {
            const userRowIndex = userRows.findIndex((row) => row[7] === user.uniqueId);
            if (userRowIndex !== -1) {
                const userRow = userRows[userRowIndex];
                const existingGroups = userRow[9] ? userRow[9].split(',') : [];
                const updatedGroups = [...new Set([...existingGroups, ...groupNames])].join(',');

                // Update the user's group information in Sheet1
                await sheets.spreadsheets.values.update({
                    spreadsheetId: REGISTRATION_SPREADSHEET_ID,
                    range: `Sheet1!J${userRowIndex + 1}`,
                    valueInputOption: 'USER_ENTERED',
                    resource: {
                        values: [[updatedGroups]],
                    },
                });
            }
        }

        res.status(200).json({ success: true, message: 'Users added to existing groups successfully' });
    } catch (err) {
        console.error('Error adding users to existing groups:', err.message);
        res.status(500).send('Error adding users to existing groups');
    }
});

const twilio = require('twilio');

const accountSid = process.env.TWILIO_ACCOUNT_SID; // Replace with your Twilio Account SID
const authToken = process.env.TWILIO_AUTH_TOKEN;   // Replace with your Twilio Auth Token
const client = twilio(accountSid, authToken);

app.post('/send-whatsapp', async (req, res) => {
    const { message, recipients } = req.body;

    if (!message || !recipients || recipients.length === 0) {
        return res.status(400).json({ error: 'Message and recipient details are required.' });
    }

    const formatPhoneNumber = (number) => {
        const cleanedNumber = number.replace(/[^\d+]/g, '');
        const formattedNumber = cleanedNumber.startsWith('+') ? cleanedNumber : `+${cleanedNumber}`;
        return /^\+\d{10,15}$/.test(formattedNumber) ? formattedNumber : null;
    };

    const validRecipients = recipients
        .map((recipient) => {
            const formattedPhone = formatPhoneNumber(recipient.phone);
            if (!formattedPhone) {
                console.log(`Invalid phone number: ${recipient.phone}`);
                return null;
            }
            return {
                ...recipient,
                phone: formattedPhone,
            };
        })
        .filter((recipient) => recipient !== null);

    if (validRecipients.length === 0) {
        return res.status(400).json({ error: 'No valid recipients found.' });
    }

    try {
        const results = await Promise.all(validRecipients.map(async (recipient) => {
            try {
                await client.messages.create({
                    from: 'whatsapp:+14155238886',
                    to: `whatsapp:${recipient.phone}`,
                    body: `Hello ${recipient.firstName} ${recipient.lastName},\n\n${message}`,
                });
                return { ...recipient, status: 'success' };
            } catch (error) {
                console.error(`Error sending WhatsApp message to ${recipient.phone}:`, error.message);
                return { ...recipient, status: 'failed', error: error.message };
            }
        }));

        res.status(200).json({
            success: true,
            message: `Messages sent successfully to ${validRecipients.length} recipients!`,
            results,
        });
    } catch (error) {
        console.error('Error sending WhatsApp messages:', error.message);
        res.status(500).json({ success: false, error: 'Failed to send messages.' });
    }
});


const { TelegramClient } = require("telegram");
const { StringSession } = require("telegram/sessions");
const { Api } = require("telegram");

const apiId = process.env.TELEGRAM_API_ID; // Replace with your Telegram API ID
const apiHash = process.env.TELEGRAM_API_HASH; // Replace with your Telegram API Hash
const stringSession = new StringSession(process.env.TELEGRAM_SESSION_STRING); // Replace with your session string

(async () => {
    const client = new TelegramClient(stringSession, apiId, apiHash, {
        connectionRetries: 5,
    });

    await client.connect();
    console.log("Telegram client connected.");

    app.post("/send-telegram", async (req, res) => {
        const { message, recipients } = req.body;
        console.log("Received Payload:", req.body);
    
        if (!message || !recipients || recipients.length === 0) {
            return res.status(400).json({ error: "Message and recipient details are required." });
        }
    
        try {
            const results = await Promise.all(
                recipients.map(async (recipient) => {
                    const { phone, firstName, middleName, lastName, email } = recipient;
    
                    try {
                        // Add the number as a contact
                        const result = await client.invoke(
                            new Api.contacts.ImportContacts({
                                contacts: [
                                    new Api.InputPhoneContact({
                                        clientId: Math.floor(Math.random() * 100000), // Unique client ID
                                        phone: phone, // Phone number
                                        firstName: firstName || "Unknown",
                                        middleName: middleName || "",
                                        lastName: lastName || "",
                                    }),
                                ],
                            })
                        );
    
                        // Check if the contact was added successfully
                        if (result.users.length > 0) {
                            console.log(`Added ${phone} (${firstName}) as a contact.`);
                        } else {
                            console.log(`Failed to add ${phone} (${firstName}) as a contact.`);
                            return { ...recipient, status: "failed", error: "Failed to add contact" };
                        }
    
                        // Send the message to the contact
                        const user = result.users[0]; // Use the first user returned in the result
                        await client.sendMessage(user.id, { message });
                        console.log(`Message sent to ${phone}`);
                        return { ...recipient, status: "success" };
                    } catch (err) {
                        console.error(`Failed to send message to ${phone}: ${err.message}`);
                        return { ...recipient, status: "failed", error: err.message };
                    }
                })
            );
    
            res.status(200).json({
                success: true,
                message: "Messages sent successfully!",
                results,
            });
        } catch (error) {
            console.error("Error sending messages:", error.message);
            res.status(500).json({ success: false, error: "Failed to send Telegram messages." });
        }
    });
})();



app.post('/send-sms', async (req, res) => {
    const { message, recipients } = req.body;

    console.log('Incoming SMS Request:', req.body);

    if (!message || !recipients || recipients.length === 0) {
        return res.status(400).json({ error: 'Message and recipient details are required.' });
    }

    try {
        const results = await Promise.all(
            recipients.map(async (recipient) => {
                const { phone, firstName, middleName, lastName, email } = recipient;
                const phoneNumber = phone.startsWith('+') ? phone : `+91${phone.trim()}`;

                try {
                    await client.messages.create({
                        from: '+12317427909', // Replace with your Twilio trial phone number
                        to: phoneNumber,
                        body: message,
                    });
                    return { ...recipient, status: "success" };
                } catch (error) {
                    console.error(`Failed to send SMS to ${phoneNumber}:`, error.message);
                    return { ...recipient, status: "failed", error: error.message };
                }
            })
        );

        res.status(200).json({
            success: true,
            message: `SMS sent successfully to ${recipients.length} recipients!`,
            results,
        });
    } catch (error) {
        console.error('Error sending SMS:', error.message);
        res.status(500).json({ success: false, error: 'Failed to send SMS.' });
    }
});

app.listen(5000, () => console.log('Server started on port 5000'));
