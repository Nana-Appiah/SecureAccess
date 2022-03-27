using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

using PortSight;
using SecureAccess;
using PortSight.SecureAccess;
using PortSight.SecureAccess.ARObjects;
using PortSight.SecureAccess.ARDataServices;
using System.Threading.Tasks;
using System.Configuration;

using SecureAuth.Models;
using System.Web.Http.Cors;
using System.Web.Cors;
using System.Data;
using System.Diagnostics;

namespace SecureAuth.Controllers
{
    [EnableCors(origins: "https://localhost:7111", headers:"*",methods:"*")]
    public class UserController : ApiController
    {

        private ARConnection conn;
        public UserController()
        {
            
        }

        private void InitializeConnectionObject()
        {
            var str = ConfigurationManager.AppSettings["connstring"].ToString();
            conn = new ARConnection(str);
            conn.ConnectToCatalog();  //ARCon object
        }

        [HttpPost]
        public bool User(string[] model)
        {
            try
            {
                InitializeConnectionObject();
                var o = ARHelper.AuthenticateUser(model[0], model[1], conn.ConnectionString, Functions.GetAES256EncryptionKey(),
                                                   Functions.GetAES256InitializationVector(), Functions.GetAES256CipherStringFormat());
                if (o == ARAuthenticationResultsEnum.OK)
                {
                    var user = new ARUser();
                    user = conn.GetUserByLogin(model[0]);

                    var u = new ARUserTicket(user);

                    //calling isAuthorized from here
                    var bln = IsAuthorized(u, model[1], model[2], conn);
                    return bln;
                }
                else { return false; }
            }
            catch(Exception ee)
            {
                Debug.Print($"error: {ee.Message}");
                return false;
            }
        }

        //[HttpGet]
        //public bool isAuthorized(string[] data)
        //{
        //    //username
        //    //resource alias (etas.admin or etas.student)
        //    //permission list (create , read,update, delete)
        //    try
        //    {
        //        var str = ConfigurationManager.AppSettings["connstring"].ToString();
        //        var conn = new ARConnection(str);
        //        conn.ConnectToCatalog();

        //        var user = new ARUser();
        //        user = conn.GetUserByLogin(data[0]);

        //        var u = new ARUserTicket(user);
        //        var membership = u.MembershipObjectAliases.Split(';');

        //        bool bln = Array.Exists(membership, x => x == data[1].ToString());

        //        //bool bln = ARHelper.IsAuthorized(data[0], data[1], data[2]);

        //        return bln;
        //    }
        //    catch (Exception x)
        //    {
        //        return false;
        //    }
        //}

        [HttpGet]
        public bool IsAuthorized(ARUserTicket ticket, string resourcealias, string permissionalias, ARConnection ARConn)
        {
            if (ARHelper.IsAuthorized(ticket.Login, resourcealias, permissionalias))
            {
                return true;
            }
            else
            {
                // gets all operators authorized for this permission
                bool returnValue = false;

                foreach (ARObject authorizedOperator in GetAuthorisedOperators(ARConn.GetResourceByAlias(resourcealias).ObjectID))
                {
                    AROperator arOperator;
                    foreach (string membership in ticket.MembershipObjectAliases.Split(';'))
                    {
                        if (membership != "")
                        {
                            if (ARConn.GetGroupByAlias(membership) != null)
                            {
                                if (authorizedOperator.ObjectID == ARConn.GetGroupByAlias(membership).ObjectID)
                                {
                                    arOperator = ARConn.GetOperatorByID(authorizedOperator.ObjectID);
                                    returnValue = arOperator.IsAuthorized(resourcealias, permissionalias);
                                    return returnValue;
                                }
                                else 
                                { 
                                    return false; 
                                }
                            }
                            else
                            { 
                                return false; 
                            }
                        }
                        else
                        {
                            return false;
                        }
                    }
                }

                return returnValue;
            }
        }


        private ARObjectsCollection GetAuthorisedOperators(int ResourceID)
        {
            ARObjectsCollection o = new ARObjectsCollection();

            DataRow dr = null; // TODO Change to default(_) if this is not a reference type /;
            DataSet ds;
            ARDBObject ardbobj = new ARDBObject();
            ARObject arobj;

            ds = ardbobj.SelectPermissionMatrix(ResourceID);

            string lastValue = "";
            int rowIndex = 0;
            int period = 0;

            if (ds.Tables[0].Rows.Count > 0)
            {

                lastValue = ds.Tables[0].Rows[0]["ChildObjectID"].ToString();
                // find the row-repeating period
                while (lastValue == ds.Tables[0].Rows[rowIndex]["ChildObjectID"].ToString())
                {
                    rowIndex += 1;
                    if (rowIndex == ds.Tables[0].Rows.Count)
                        break;
                }

                period = rowIndex;

                for (rowIndex = 0; rowIndex <= ds.Tables[0].Rows.Count - 1; rowIndex += period)
                {
                    arobj = conn.GetObjectByID(int.Parse(ds.Tables[0].Rows[rowIndex]["ChildObjectID"].ToString()));
                    o.Add(arobj);
                }
            }

            return o;
        }


    }
}
