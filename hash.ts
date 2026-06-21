import { hashPassword } from './fluxer_api/src/api/utils/PasswordUtils';
async function main() {
  const hash = await hashPassword('fa_123456789012345678_EncoraManualKey000000000000');
  console.log(hash);
}
main();
