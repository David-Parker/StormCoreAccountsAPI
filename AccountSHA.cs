namespace WoWDatabase
{
    using System;
    using System.Text;
    using System.Security.Cryptography;

    /// <summary>
    /// Class generates the password SHAs for both the account and battle net account databases for WoW private servers.
    /// </summary>
    public static class AccountSHA
    {
        /// <summary>
        /// Blizzard's account database SHA1 hashing algorithm, uses the account name and a colon as a salt.
        /// </summary>
        /// <param name="account"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string CreateAccountPasswordSha(string account, string password)
        {
            if (String.IsNullOrEmpty(account))
            {
                throw new ArgumentNullException(nameof(account));
            }

            if (String.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            account = account.ToUpperInvariant();
            password = password.ToUpperInvariant();

            string combine = account + ":" + password;
            byte[] data = Encoding.ASCII.GetBytes(combine);

            using (SHA1 shaM = new SHA1Managed())
            {
                return ByteArrayToString(shaM.ComputeHash(data));
            }
        }

        /// <summary>
        /// Blizzard's battle net account SHA1 password hashing algorithm, uses SHA256 and uses a hash of the email as a salt for the hash of the password.
        /// </summary>
        /// <param name="account"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string CreateBattleNetAccountPasswordSha(string email, string password)
        {
            if (String.IsNullOrEmpty(email))
            {
                throw new ArgumentNullException(nameof(email));
            }

            if (String.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            email = email.ToUpperInvariant();
            password = password.ToUpperInvariant();
            byte[] emailBytes = Encoding.ASCII.GetBytes(email);
            string emailHash;

            using (SHA256 shaM = new SHA256Managed())
            {
                emailHash = ByteArrayToString(shaM.ComputeHash(emailBytes));

                string combine = emailHash + ":" + password;

                byte[] combineBytes = Encoding.ASCII.GetBytes(combine);

                return ByteArrayToString(shaM.ComputeHash(combineBytes), true);
            }
        }

        /// <summary>
        /// Converts the byte array to an uppercased hex string with no 0x, ability to reverse the byte order.
        /// </summary>
        /// <param name="ba"></param>
        /// <param name="reverse"></param>
        /// <returns></returns>
        public static string ByteArrayToString(byte[] ba, bool reverse = false)
        {
            if(ba == null)
            {
                throw new ArgumentNullException(nameof(ba));
            }

            StringBuilder hex = new StringBuilder(ba.Length * 2);

            if(reverse == false)
            {
                for(int i = 0; i < ba.Length; i++)
                {
                    Byte b = ba[i];
                    hex.AppendFormat("{0:X2}", b);
                }
            }
            else
            {
                for (int i = ba.Length - 1; i >= 0; i--)
                {
                    Byte b = ba[i];
                    hex.AppendFormat("{0:X2}", b);
                }
            }

            return hex.ToString();
        }
    }
}
