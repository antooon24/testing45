import { readFile } from 'fs/promises';

try {
    // Read the service account JSON file
    const serviceAccount = await readFile('serviceAccountKey.json', 'utf8');

    // Encode it to base64
    const base64ServiceAccount = Buffer.from(serviceAccount).toString('base64');

    // Output the result
    console.log(base64ServiceAccount);
} catch (error) {
    console.error('Error encoding the file to Base64:', error);
}
