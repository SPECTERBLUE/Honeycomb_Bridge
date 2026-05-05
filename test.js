function str_pad(byte) {
    var zero = '0';
    var hex = byte.toString(16);    
    var tmp = 2 - hex.length;
    return zero.substr(0, tmp) + hex;
}
function convertToIST(unixTime) {
    // Convert to milliseconds
    var date = new Date(unixTime * 1000);
    // IST offset is +5:30
    date.setHours(date.getUTCHours() + 5);
    date.setMinutes(date.getUTCMinutes() + 30);
    // Format the date in human-readable format
    return date.toLocaleString('en-GB', { timeZone: 'Asia/Kolkata' });
}
function Decode(fPort, bytes, variables) {
    var baseName = "";  // Example base name, this can be set dynamically
    var baseTime = Math.floor(Date.now() / 1000);  // Current timestamp in seconds
    var baseUnit = "A";  // Example base unit
    var baseVersion = 5;  // Example base version
    var decode = [];
    var base =  { bn: baseName, bt: baseTime, bu: baseUnit, bver: baseVersion } ;
    if (fPort == 2) {
        if (bytes.length == 11) {
            var systemTimestamp = (bytes[7] << 24 | bytes[8] << 16 | bytes[9] << 8 | bytes[10]);
            var systemTimestampIST = convertToIST(systemTimestamp);
            decode.push(
                { bn: baseName, bt: baseTime, bu: baseUnit, bver: baseVersion, n: "temperature", v: parseFloat(((bytes[0] << 24 >> 16 | bytes[1]) / 100).toFixed(2)), u: "Cel" },
                { n: "humidity", v: parseFloat(((bytes[2] << 24 >> 16 | bytes[3]) / 10).toFixed(1)), u: "%" },
                { n: "temperature_ds", v: parseFloat(((bytes[4] << 24 >> 16 | bytes[5]) / 100).toFixed(2)), u: "Cel" },
                { n: "timestamp", vs: systemTimestampIST }
);
        } else {
            decode.push(
                { bn: baseName, bt: baseTime, bu: baseUnit, bver: baseVersion, n: "Status", v: "RPL data or sensor reset" }
            );
        }
    }
    if (fPort == 3) {
        decode.push(
            { bn: baseName, bt: baseTime, bu: baseUnit, bver: baseVersion, n: "Status", v: "Data retrieved, you need to parse it by the application server" }
        );
    }

    if (fPort == 4) {
        decode.push(
            { bn: baseName, bt: baseTime, bu: baseUnit, bver: baseVersion, n: "DS18B20_ID", v: str_pad(bytes[0]) + str_pad(bytes[1]) + str_pad(bytes[2]) + str_pad(bytes[3]) + str_pad(bytes[4]) + str_pad(bytes[5]) + str_pad(bytes[6]) + str_pad(bytes[7]), u: "ID" }
        );
    }

    if (fPort == 5) {
        decode.push(
            { bn: baseName, bt: baseTime, bu: baseUnit, bver: baseVersion, n: "Sensor_Model", v: bytes[0], u: "model" },
            { n: "Firmware_Version", vs: str_pad((bytes[1] << 8) | bytes[2]), u: "version" },
            { n: "Freq_Band", v: bytes[3], u: "Hz" },
            { n: "Sub_Band", v: bytes[4], u: "sub" },
            { n: "Bat_mV", v: (bytes[5] << 8 | bytes[6]), u: "mV" }
        );
    }
    return decode;
}   