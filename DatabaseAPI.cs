namespace WoWDatabase
{
    using MySql.Data.MySqlClient;
    using System;
    using System.Collections.Generic;
    using System.Data.Common;
    using System.Threading.Tasks;

    /// <summary>
    /// Class provides a convienent API to create accounts in the Battle.Net accounts tables for StormCore WoW private servers.
    /// </summary>
    public class DatabaseAPI
    {
        private string connectionString;

        /// <summary>
        /// Connection string is a MySQL connection string that is configured for the auth table.
        /// </summary>
        /// <param name="connectionString"></param>
        public DatabaseAPI(string connectionString)
        {
	        this.connectionString = connectionString;
        }

        /// <summary>
        /// Creates a new user account. There are two account databases, one called account and one called battlenet_account. This method inserts into both.
        /// </summary>
        /// <param name="account"></param>
        /// <param name="email"></param>
        /// <param name="password"></param>
        public async Task CreateAccount(string email, string password)
        {
            if (String.IsNullOrEmpty(email))
            {
                throw new ArgumentNullException(nameof(email));
            }

            if (String.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            if(password.Length < 6)
            {
                throw new InvalidOperationException("Passwords must be at least 6 characters long.");
            }

            CheckValidString(email);
            CheckValidString(password);

            // Check if this account exists
            using (MySqlConnection connection = new MySqlConnection(connectionString))
            {
                connection.Open();

                using (MySqlCommand command = new MySqlCommand(String.Format("SELECT email FROM auth.battlenet_accounts WHERE email = '{0}';", email), connection))
                using (DbDataReader reader = await command.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        throw new InvalidOperationException("The account already exists, please use a different email.");
                    }
                }

                // Inserting into two seperate tables requires a transaction in order to prevent state corruption.
                using (MySqlTransaction trans = connection.BeginTransaction())
                {
                    email = email.ToUpperInvariant();
                    int id = await GetNextId();
                    string shapassbnet = AccountSHA.CreateBattleNetAccountPasswordSha(email, password);
                    string joindate = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
                    string username = id.ToString() + "#1"; // Don't ask, this is the expected internal account format from Blizzard.
                    string shapassaccount = AccountSHA.CreateAccountPasswordSha(username, password);

                    try
                    {
                        // Create the battle.net account
                        using (MySqlCommand command = new MySqlCommand(String.Format("INSERT INTO auth.battlenet_accounts (id, email, sha_pass_hash, joindate) VALUES ('{0}', '{1}', '{2}', '{3}');", id, email, shapassbnet, joindate), connection, trans))
                        {
                            await command.ExecuteNonQueryAsync();
                        }

                        // Create the account
                        using (MySqlCommand command = new MySqlCommand(String.Format("INSERT INTO auth.account (id, username, sha_pass_hash, email, reg_mail, joindate, battlenet_account, battlenet_index) VALUES ('{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '1');", id, username, shapassaccount, email, email, joindate, id), connection, trans))
                        {
                            await command.ExecuteNonQueryAsync();
                        }
                    }
                    catch
                    {
                        trans.Rollback();
                        throw;
                    }

                    trans.Commit();
                }
            }
        }

        /// <summary>
        /// Gets the next id for use in creating a new account.
        /// </summary>
        /// <returns></returns>
        private async Task<int> GetNextId()
        {
            using (MySqlConnection connection = new MySqlConnection(connectionString))
            {
                connection.Open();
                MySqlCommand command = new MySqlCommand("SELECT max(id) as rownum FROM auth.battlenet_accounts;", connection);
                return Convert.ToInt32(await command.ExecuteScalarAsync()) + 1;
            }
        }

        /// <summary>
        /// Reduces the chance of having a SQL injection attack. Checks if the string is valid, and does not contain escape characters.
        /// </summary>
        /// <param name="value"></param>
        private void CheckValidString(string value)
        {
            if(value.Length > 50)
            {
                throw new InvalidOperationException("Values cannot be greater than 50 characters in length.");
            }

            HashSet<char> illegalChars = new HashSet<char>()
            {
                '\'', '"', '\\'
            };

            foreach(char c in value)
            {
                if(illegalChars.Contains(c))
                {
                    throw new InvalidOperationException("Value contains an illegal character.");
                }
            }
        }
    }
}
