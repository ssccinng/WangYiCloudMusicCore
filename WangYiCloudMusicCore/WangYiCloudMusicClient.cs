using System.Buffers.Text;
using System.Globalization;
using System.Net.Http.Json;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WangYiCloudMusicCore;


public class WangYiCloudMusicClient
{
    //private static HttpClient _httpClient = new() { BaseAddress = new Uri("https://music.163.com/") };
    //private static HttpClient _httpClient = new();

    //Accept-Encoding: gzip,deflate,sdch
    static string header = @"Accept: */*
            Accept-Language: zh-CN,zh;q=0.8,gl;q=0.6,zh-TW;q=0.4
            Connection: keep-alive
            Host: music.163.com
            Referer: http://music.163.com/search/
            User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36";
    private static HttpClient _httpClient = Init();
    private static HttpClient _httpClient1 = new();

    public WangYiCloudMusicClient()
    {

    }

    static HttpClient Init()
    {
        HttpClient http = new() { BaseAddress = new Uri("https://music.163.com/") };
        foreach (var item in header.Split('\n'))
        {
            var data = item.Split(": ");
            //System.Console.WriteLine(data[0] + ": " + data[1]);
            http.DefaultRequestHeaders.Add(data[0].Trim(), data[1].Trim());
        }
        return http;
    }

    public static async Task<bool> DownloadMusicAsync(string path, string url)
    {
        var res = await _httpClient1.GetAsync(url);
        if (res.IsSuccessStatusCode)
        {
            await File.WriteAllBytesAsync(path, await res.Content.ReadAsByteArrayAsync());
            return true;
        }
        return false;
    }
    
    public static async Task SearchMusic(string name)
    {
        
    }
/// <summary>
/// 获取声音主播的音乐列表
/// </summary>
/// <param name="url"></param>
/// <returns></returns>
    public static async Task<IEnumerable<MusicInfo>> GetDjradioListAsync(string url)
{
   var res = await _httpClient.GetAsync(url);
   if (res.IsSuccessStatusCode)
   {
       List<MusicInfo> musicInfos = new();
       var danier = await res.Content.ReadAsByteArrayAsync();
       var html = Encoding.UTF8.GetString(await res.Content.ReadAsByteArrayAsync());
       var matches = Regex.Matches(html,
           @"(?m)songlist-(?<Id>\d+)[\s\S]+?<a href=""(?<url>/program\?id=(?<PId>\d+)?)"" title="".+?"">(?<name>.+?)</a>");
       foreach (Match match in matches)
       {
           musicInfos.Add(new MusicInfo
           {
               Name = match.Groups["name"].Value,
               Url = match.Groups["url"].Value,
               Id = long.Parse(match.Groups["Id"].Value)
           });
       }
       return musicInfos;
   }

   return Enumerable.Empty<MusicInfo>();
}


    public static async Task<IEnumerable<MusicInfo>> GetDjradioListAsync(int id)
    {
        //return await GetDjradioListAsync($"https://music.163.com/djradio?id={id}&_hash=programlist&limit=10000");
        return await GetDjradioListAsync($"djradio?id={id}&_hash=programlist&limit=10000");
    }
    public static async Task<bool> GetMusicRawUrl(string url)
    {

        return false;
    }

    private static Encrypyed _encrypyed = new Encrypyed();
    public static async Task<string> GetMusicRawUrl(MusicInfo musicInfo, int bitRate = 320000)
    {
        string url = "weapi/song/enhance/player/url?csrf_token=";
        string data = JsonSerializer.Serialize(new
        {
            ids = new []{musicInfo.Id}, br = bitRate, csrf_token= ""
        });
        var data1 = _encrypyed.EncryptedRequest(data);
        //var res = await _httpClient.PostAsJsonAsync(url, data);
        var res = await _httpClient.PostAsync(url, new FormUrlEncodedContent(data1));
        //Console.WriteLine(res.IsSuccessStatusCode);
        //Console.WriteLine(res.StatusCode);
        var datares = await res.Content.ReadAsStringAsync();
        //Console.WriteLine();
        return JsonDocument.Parse(datares).RootElement.GetProperty("data")[0].GetProperty("url").GetString();
        //return await GetMusicRawUrl(musicInfo.Url);
    }
}


public class Encrypyed
{
    private string _moudulus =
        "00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7";

    private string _nonce = "0CoJUm6Qyw8W8jud";
    private string _pubKey = "010001";
    Aes _aes = Aes.Create();
    RSA _rsa = RSA.Create();

    public Dictionary<string, string> EncryptedRequest(string text)
    {
        //text = "{\"ids\": [33872921], \"br\": 320000, \"csrf_token\": \"\"}";
        //Console.WriteLine("objtext: " + text);
        var secKey = CreateSecretKey(16);
        secKey = Encoding.UTF8.GetBytes("2c8b4b6436506280");
        //Console.WriteLine("EncryptedRequest secKey: " + Encoding.UTF8.GetString(secKey));
        var cc = AesEncrypt(text, _nonce);
        //Console.WriteLine("_nonce + text: " + cc);
        var encText = AesEncrypt(cc, Encoding.UTF8.GetString(secKey));
        //Console.WriteLine("encText: " + encText);
        var encSecKey = RsaEncrypt(secKey, _pubKey, _moudulus);

        //Console.WriteLine(JsonSerializer.Serialize(new { @params = encText, encSecKey = encSecKey }));
        return new Dictionary<string, string> { { "params", encText }, {"encSecKey", encSecKey } };
    }
    public string AesEncrypt(string text, string seckey)
    {
        //Console.WriteLine("aes_encrypt secKey: " + seckey);
        int pad = 16 - text.Length % 16;
        //Console.WriteLine("pad: " + pad);
        char[] padArray = new char[pad];
        for (int i = 0; i < pad; i++)
        {
            padArray[i] = (char)pad;
        }
        _aes.Key = Encoding.UTF8.GetBytes(seckey);
        text = $"{text}{string.Join("", padArray)}";
        //Console.WriteLine("text: (" + text + ")");
        //Console.WriteLine(text.Length);
        var cipText = _aes.EncryptCbc
            (
            Encoding.UTF8.GetBytes(text),
            Encoding.UTF8.GetBytes("0102030405060708")
            );
        //Console.WriteLine("cipText: " + cipText);
        byte[] aa = new byte[cipText.Length + 200];
        Base64.EncodeToUtf8(cipText[..text.Length], aa, out int bytesConsumed, out int bytesWritten);
        //Console.WriteLine("bytesWritten: " + bytesWritten);
        //Console.WriteLine(Encoding.UTF8.GetString(aa, 0,bytesWritten));
        return Encoding.UTF8.GetString(aa, 0, bytesWritten);
    }

    public string RsaEncrypt(Byte[] text, string pubKey, string moudulus)
    {
        text = text.Reverse().ToArray();
        var gg = Encoding.UTF8.GetString(text);
        //Converter.
        var hext = BitConverter.ToString(text);
        //gg = "6827c958f2099be8";
        var pubbig = int.Parse(pubKey, NumberStyles.HexNumber);
        var moudulusbig = BigInteger.Parse(moudulus, NumberStyles.HexNumber);
        //Console.WriteLine("gg: " + gg);
        //Console.WriteLine("gg: " + ConvertToHex(gg));
        //Console.WriteLine("gg: " + BigInteger.Parse(ConvertToHex(gg), NumberStyles.HexNumber));
        //Console.WriteLine("gg: " + BigInteger.Parse(gg, NumberStyles.HexNumber));

        //Console.WriteLine("pubbig: " + pubbig);
        //Console.WriteLine("moudulusbig: " + moudulusbig);
        var rs = PowerBySquaringDS(BigInteger.Parse(ConvertToHex(gg), NumberStyles.HexNumber),
            pubbig, 
            moudulusbig);
        var rss = rs.ToString("x256");
        //Console.WriteLine("rs: " + rs);
        //Console.WriteLine("rss: " + rs.ToString("x256"));
        // Console.WriteLine(rss);
        return rss;
    }

    public byte[] CreateSecretKey(int size)
    {
        Byte[] randStr = new Byte[16];
         Random.Shared.NextBytes(randStr);
         Console.WriteLine(Convert.ToHexString(randStr));
         return Encoding.UTF8.GetBytes(Convert.ToHexString(randStr).ToLower())[..16];
         return randStr;
         // return string.Join("", randStr);
    }
    public static string ConvertToHex(string asciiString)
    {
        string hex = "";
        foreach (char c in asciiString)
        {
            int tmp = c;
            hex += String.Format("{0:x2}", (uint)System.Convert.ToUInt32(tmp.ToString()));
        }
        return hex;
    }
    public void Test()
    {
        // RsaEncrypt(new byte[] {15, 15}, _pubKey, _moudulus);
    }
    // private static byte[] Hex2Binary(byte[] hex)
    // {
    //     var chars = hex;
    //     var bytes = new List<byte>();
    //     for (int index = 0; index < chars.Length; index += 2)
    //     {
    //         var chunk = new string(chars, index, 2);
    //         bytes.Add(byte.Parse(chunk, NumberStyles.AllowHexSpecifier));
    //     }
    //     return bytes.ToArray();
    // }
    static string Hex2Binary1(string hexvalue)
    {
        StringBuilder binaryval = new StringBuilder();
        for(int i=0; i < hexvalue.Length; i++)
        {
            string byteString = hexvalue.Substring(i, 1);
            byte b = Convert.ToByte(byteString, 16);
            binaryval.Append(Convert.ToString(b, 2).PadLeft(4, '0'));
        }
        return binaryval.ToString();
    }

    
    public static long PowerBySquaring(long baseNumber, int exponent, int mod)
    {
        long result = 1;
        while (exponent != 0)
        {
            if ((exponent & 1) == 1)
            {
                result *= baseNumber;
                result %= mod;
            }
            exponent >>= 1;
            baseNumber *= baseNumber;
            baseNumber %= mod;
        }

        return result;
    }
    
    public static BigInteger PowerBySquaringDS(BigInteger baseNumber, int exponent, BigInteger mod)
    {
        BigInteger result = 1;
        while (exponent != 0)
        {
            if ((exponent & 1) == 1)
            {
                result *= baseNumber;
                result %= mod;
            }
            exponent >>= 1;
            baseNumber *= baseNumber;
            baseNumber %= mod;
        }

        return result;
    }
}
