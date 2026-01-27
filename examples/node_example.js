/**
 * Example: Using Licenz from Node.js via CLI
 * 
 * This demonstrates how to integrate the license system into Node.js applications.
 */

const { execSync } = require('child_process');

class LicenseManager {
    constructor(cliPath = 'licenz') {
        this.cli = cliPath;
    }

    _exec(args, options = {}) {
        const cmd = `${this.cli} ${args.join(' ')}`;
        try {
            const result = execSync(cmd, {
                encoding: 'utf-8',
                stdio: options.silent ? 'pipe' : undefined
            });
            return { success: true, output: result };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    keygen(outputDir = 'keys', size = 2048, force = false) {
        const args = ['keygen', '--dir', outputDir, '--size', size.toString()];
        if (force) args.push('--force');
        return this._exec(args);
    }

    generate({ customer, product, serial, days = 365, features = [], output = 'license.lic', privateKey = 'keys/private.pem' }) {
        const args = ['generate', '--customer', customer, '--product', product, '--days', days.toString(), '--key', privateKey, '--output', output];
        if (serial) args.push('--serial', serial);
        if (features.length > 0) args.push('--features', features.join(','));
        return this._exec(args);
    }

    verify(licensePath = 'license.lic', publicKey = 'keys/public.pem', skipHardware = false) {
        const args = ['verify', '--license', licensePath, '--key', publicKey];
        if (skipHardware) args.push('--skip-hardware');
        return this._exec(args, { silent: true }).success;
    }

    info(licensePath = 'license.lic', publicKey = 'keys/public.pem') {
        const args = ['info', '--license', licensePath, '--key', publicKey, '--json'];
        const result = this._exec(args, { silent: true });
        return result.success ? JSON.parse(result.output) : null;
    }
}

// Example usage
const lm = new LicenseManager();

console.log('Generating keys...');
lm.keygen('keys', 2048, true);
console.log('✓ Keys generated');

console.log('\nGenerating license...');
lm.generate({ customer: 'ACME Corp', product: 'MyNodeApp', features: ['basic', 'premium'] });
console.log('✓ License generated');

console.log('\nVerifying license...');
if (lm.verify('license.lic', 'keys/public.pem', true)) {
    console.log('✓ License is VALID');
} else {
    console.log('✗ License is INVALID');
}

const info = lm.info();
if (info) {
    console.log('\nLicense details:');
    console.log(`  Customer: ${info.license.customer_id}`);
    console.log(`  Features: ${info.license.features.join(', ')}`);
}
