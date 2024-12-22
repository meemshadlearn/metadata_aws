/***************************************************************************************************
 * Code that will query the metadata of an instance within AWS and provide a Json formatted output 
 * *************************************************************************************************
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using Amazon.Runtime;
using ThirdParty.Json.LitJson;
using System.Globalization;
using Amazon.Runtime.Internal.Util;
using Amazon.Util.Internal;
using Amazon.Util;

namespace Amazon.EC2.Util
{
    /// <summary>
    /// EC2 Instance Metadata details are available at AWS IP - http://169.254.169.254
    /// If this class is used on a non-EC2 instance, the properties in this class
    /// will return null.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Amazon EC2 instances can access instance-specific metadata, as well as data supplied when launching the instances, using a specific URI.
    /// </para>
    /// Reference taken from EC2 Metadata <see href="http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AESDG-chapter-instancedata.html"/>
    /// </para>
    /// </remarks>
	
    public static class EC2Metadata
    {
        private static string
            EC2_METADATA_SVC = "http://169.254.169.254",
            EC2_METADATA_ROOT = EC2_METADATA_SVC + "/latest/meta-data",
            EC2_USERDATA_ROOT = EC2_METADATA_SVC + "/latest/user-data/",
            EC2_APITOKEN_URL = EC2_METADATA_SVC + "latest/api/token";

        private static Dictionary<string, string> _cache = new Dictionary<string, string>();

        private static readonly string _userAgent = InternalSDKUtils.BuildUserAgentString(string.Empty);

        /// <summary>
        /// The AMI ID used to launch the instance.
        /// </summary>
        public static string AmiId
        {
            get { return FetchData("/ami-id"); }
        }

        /// <summary>
        /// The index of this instance in the reservation.
        /// </summary>
        public static string AmiLaunchIndex
        {
            get { return FetchData("/ami-launch-index"); }
        }

        /// <summary>
        /// The manifest path of the AMI with which the instance was launched.
        /// </summary>
        public static string AmiManifestPath
        {
            get { return FetchData("/ami-manifest-path"); }
        }

        /// <summary>
        /// The private hostname of the instance.
        /// In cases where multiple network interfaces are present,
        /// this refers to the eth0 device (the device for which the device number is 0).
        /// </summary>
        public static string Hostname
        {
            get { return FetchData("/hostname"); }
        }

        /// <summary>
        /// The ID of this instance.
        /// </summary>
        public static string InstanceId
        {
            get { return FetchData("/instance-id"); }
        }

        /// <summary>
        /// The type of instance. 
        /// </summary>
        public static string InstanceType
        {
            get { return FetchData("/instance-type"); }
        }

        /// <summary>
        /// The ID of the kernel launched with this instance, if applicable.
        /// </summary>
        public static string KernelId
        {
            get { return GetData("kernel-id"); }
        }

        /// <summary>
        /// The local hostname of the instance. In cases where multiple network interfaces are present, 
        /// this refers to the eth0 device (the device for which device-number is 0).
        /// </summary>
        public static string LocalHostname
        {
            get { return FetchData("/local-hostname"); }
        }

        /// <summary>
        /// The instance's MAC address. In cases where multiple network interfaces are present, 
        /// this refers to the eth0 device (the device for which device-number is 0).
        /// </summary>
        public static string MacAddress
        {
            get { return FetchData("/mac"); }
        }

        /// <summary>
        ///  The private IP address of the instance. In cases where multiple network interfaces are present, 
        ///  this refers to the eth0 device (the device for which device-number is 0).
        /// </summary>
        public static string PrivateIpAddress
        {
            get { return FetchData("/local-ipv4"); }
        }

        /// <summary>
        /// The Availability Zone in which the instance launched.
        /// </summary>
        public static string AvailabilityZone
        {
            get { return FetchData("/placement/availability-zone"); }
        }

        /// <summary>
        /// Product codes associated with the instance, if any. 
        /// </summary>
        public static IEnumerable<string> ProductCodes
        {
            get { return GetItems("/product-codes"); }
        }

        /// <summary>
        /// Public key. Only available if supplied at instance launch time.
        /// </summary>
        public static string PublicKey
        {
            get { return FetchData("/public-keys/0/openssh-key"); }
        }

        /// <summary>
        /// The ID of the RAM disk specified at launch time, if applicable.
        /// </summary>
        public static string RamdiskId
        {
            get { return FetchData("/ramdisk-id"); }
        }

        /// <summary>
        /// ID of the reservation.
        /// </summary>
        public static string ReservationId
        {
            get { return FetchData("/reservation-id"); }
        }

        /// <summary>
        /// The names of the security groups applied to the instance. 
        /// </summary>
        public static IEnumerable<string> SecurityGroups
        {
            get { return GetItems("/security-groups"); }
        }

        /// <summary>
        /// Returns information about the last time the instance profile was updated, 
        /// including the instance's LastUpdated date, InstanceProfileArn, and InstanceProfileId.
        /// </summary>
        public static IAMInfo IAMInstanceProfileInfo
        {
            get
            {
                var json = GetData("/iam/info");
                if (null == json)
                    return null;
                IAMInfo info;
                try
                {
                    info = JsonMapper.ToObject<IAMInfo>(json);
                }
                catch 
                { 
                    info = new IAMInfo { Code = "Failed", Message = "Could not parse response from metadata service." }; 
                }
                return info;
            }
        }

        /// <summary>
        /// Returns the temporary security credentials (AccessKeyId, SecretAccessKey, SessionToken, and Expiration) 
        /// associated with the IAM roles on the instance.
        /// </summary>
        public static IDictionary<string, IAMSecurityCredential> IAMSecurityCredentials
        {
            get
            {
                var list = GetItems("/iam/security-credentials");
                if (list == null)
                    return null;

                var creds = new Dictionary<string, IAMSecurityCredential>();
                foreach (var item in list)
                {
                    var json = GetData("/iam/security-credentials/" + item);
                    try
                    {
                        var cred = JsonMapper.ToObject<IAMSecurityCredential>(json);
                        creds[item] = cred;
                    }
                    catch 
                    {
                        creds[item] = new IAMSecurityCredential { Code = "Failed", Message = "Could not parse response from metadata service." };
                    }
                }

                return creds;
            }
        }

    }

    /// <summary>
    /// Returns information about the last time the instance profile was updated, 
    /// including the instance's LastUpdated date, InstanceProfileArn, and InstanceProfileId.
    /// </summary>
  
    public class IAMInfo
    {
        /// <summary>
        /// The status of the instance profile
        /// </summary>
        public string Code { get; set; }

        /// <summary>
        /// Further information about the status of the instance profile
        /// </summary>
        public string Message { get; set; }

        /// <summary>
        /// The date and time the instance profile was updated
        /// </summary>
        public DateTime LastUpdated { get; set; }

        /// <summary>
        /// The Amazon Resource Name (ARN) of the instance profile
        /// </summary>
        public string InstanceProfileArn { get; set; }

        /// <summary>
        /// The Id of the instance profile
        /// </summary>
        public string InstanceProfileId { get; set; }
    }

    /// <summary>
    /// The temporary security credentials (AccessKeyId, SecretAccessKey, SessionToken, and Expiration) associated with the IAM role.
    /// </summary>

    public class IAMSecurityCredential
    {
        /// <summary>
        /// The status of the security credential
        /// </summary>
        public string Code { get; set; }

        /// <summary>
        /// Further information about the status of the instance profile
        /// </summary>
        public string Message { get; set; }

        /// <summary>
        /// The date and time the security credential was last updated
        /// </summary>
        public DateTime LastUpdated { get; set; }

        /// <summary>
        /// The type of the security credential
        /// </summary>
        public string Type { get; set; }

        /// <summary>
        /// The uniqe id of the security credential
        /// </summary>
        public string AccessKeyId { get; set; }

        /// <summary>
        /// The secret key used to sign requests
        /// </summary>
        public string SecretAccessKey { get; set; }
        
        /// <summary>
        /// The security token
        /// </summary>
        public string Token { get; set; }

        /// <summary>
        /// The date and time when these credentials expire
        /// </summary>
        public DateTime Expiration { get; set; }
    }

        }
/***************************************************************************************************
 * Code that will query the metadata of an instance within AWS and provide a Json formatted output has been referred from 
 * https://github.com/aws/aws-sdk-net/blob/master/sdk/src/Services/EC2/Custom/_bcl/Util/EC2Metadata.cs for writing C# code for functions and Variables
 * *************************************************************************************************
 */
