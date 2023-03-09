namespace MultipleAuthenticatons.Utils
{
    public static class StringEqualityExtensions
    {
        public static bool EqualsCaseInsensitive(this string s1, string s2)
        {
            return s1.Equals(s2, StringComparison.OrdinalIgnoreCase);
        }
    }
}
