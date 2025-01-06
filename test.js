const { google } = require('googleapis');
const credentials = require('./credentials.json');

const auth = new google.auth.GoogleAuth({
    credentials,
    scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});

const sheets = google.sheets({ version: 'v4', auth });

const SPREADSHEET_ID = '1dFPh2HKhkrZ3sXk8PVLb7T2LCVmvC2WG8LYo7eRWpBs';

async function testAccess() {
    try {
        const response = await sheets.spreadsheets.get({
            spreadsheetId: SPREADSHEET_ID,
        });
        console.log('Success! Spreadsheet details:', response.data);
    } catch (error) {
        console.error('Error accessing spreadsheet:', error);
    }
}

testAccess();
