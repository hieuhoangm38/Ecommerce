using System;
using System.Security.Cryptography;
using WebApi.Entities;
using WebApi.Helpers;
using static Org.BouncyCastle.Asn1.Cmp.Challenge;
using System.Linq;
using WebApi.Models.Users;
using WebApi.Services;
using StackExchange.Redis;

namespace WebApi.Authorization
{

    public interface IOtpUtils
    {
        public string GenerateOtp(User user);

        public bool VerifyOtpss(User user,string otpRequest);
    }
    public class OtpUtils : IOtpUtils
    {
        private readonly DataContext _context;
        private readonly IConnectionMultiplexer _multiplexer;
        private readonly IDatabase _redisCache;
        
        public OtpUtils(DataContext context,IConnectionMultiplexer multiplexer) 
        { 
            _context = context;
            _multiplexer = multiplexer;
            _redisCache = _multiplexer.GetDatabase();   
        }
        public string GenerateOtp(User user)
        {
            Random random = new Random();
            const string chars = "0123456789";
            string randomString = new string(Enumerable.Repeat(chars, 4)
              .Select(s => s[random.Next(s.Length)]).ToArray());

            //var ListOtp = from otpDB in _context.Otp where otpDB.UserId == user.Id select otpDB;
            if (!_redisCache.KeyExists($"otp:user{user.Id}"))
            {
                _redisCache.StringSet($"otp:user{user.Id}", randomString,TimeSpan.FromMinutes(2));
                return randomString;
            }
            else
                throw new Exception("Tài khoản này đã được đăng nhập ở một nơi khác");
            //foreach (var element in ListOtp)
            //{
            //    if (element.OtpCodes == randomString && element.Expries <= DateTime.UtcNow)
            //    {
            //        GenerateOtp(user);
            //    }
            //}

            //Otp otp = new Otp
            //{
            //    OtpCodes = randomString ,
            //    Created = DateTime.UtcNow,
            //    Expries = DateTime.UtcNow.AddMinutes(10),
            //    UserId = user.Id,
            //};
            //_context.Otp.Add(otp);
            //_context.SaveChanges();
            

            //bool OtpIsUnique = !_context.Otp.Any(a => a.Otps.Any(t => t.OtpCode == otp.OtpCode));

            //User user1 = _context.Users.FirstOrDefault(x => x.Id == user.Id);


            //_context.Otp.Add(otp);
            //_context.SaveChanges();
            ////lỗi 
            //bool OtpIsUnique = user1.Otps.Any(x => x.OtpCode == randomString);
            //if (!OtpIsUnique)
            //    return GenerateOtp(user);

            //return otp.OtpCodes;
        }

        public bool VerifyOtpss(User user,string otpRequest)
        {
            //User user = _context.Users.SingleOrDefault(x => x.Otps.Any(t => t.OtpCode == otp));          
            //Otp otps = _context.Otp.SingleOrDefault(x => x.OtpCodes == otp);

            //Otp OtpVerifysucessful = user.Otps.FirstOrDefault( x => x.OtpCodes == otp);
            //if(OtpVerifysucessful == null || !OtpVerifysucessful.IsActive)
            //{
            //    return false;
            //}
            //_context.Otp.FirstOrDefault(x => x.Id == user.Id);

            //var ListOtp = from otp in _context.Otp where otp.UserId == user.Id select otp;

            //foreach (var otp in ListOtp)
            //{
            //    if(otp.OtpCodes == otpRequest && otp.Expries <= DateTime.UtcNow)
            //    {
            //        return true;
            //    }
            //}
            //return false;
            if(otpRequest == _redisCache.StringGet($"otp:user{user.Id}"))
            {
                return true;
            }
            return false;
            
        }
    }
}
