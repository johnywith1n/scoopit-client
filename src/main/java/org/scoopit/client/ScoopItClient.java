package org.scoopit.client;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import oauth.signpost.OAuth;
import oauth.signpost.OAuthConsumer;
import oauth.signpost.OAuthProvider;
import oauth.signpost.basic.DefaultOAuthConsumer;
import oauth.signpost.basic.DefaultOAuthProvider;
import oauth.signpost.exception.OAuthCommunicationException;
import oauth.signpost.exception.OAuthExpectationFailedException;
import oauth.signpost.exception.OAuthMessageSignerException;
import oauth.signpost.exception.OAuthNotAuthorizedException;
import oauth.signpost.signature.HmacSha1MessageSigner;

public class ScoopItClient
{
	private static final Logger LOGGER = LoggerFactory.getLogger(ScoopItClient.class);
	
	private static final ResourceBundle PROPS = ResourceBundle.getBundle("oauth");
	private static final String CONSUMER_KEY = PROPS.getString("consumer_key");
	private static final String CONSUMER_SECRET = PROPS.getString("consumer_secret");
	private static final String REQUEST_TOKEN_URL = "http://www.scoop.it/oauth/request";
	private static final String AUTHORIZE_URL = "https://www.scoop.it/oauth/authorize";
	private static final String ACCESS_TOKEN_URL = "http://www.scoop.it/oauth/access";
	private static final String BASE_API_URL = "http://www.scoop.it";	
	
	private static final OAuthConsumer CONSUMER = new DefaultOAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET);
	private static final OAuthProvider PROVIDER = new DefaultOAuthProvider(REQUEST_TOKEN_URL, ACCESS_TOKEN_URL, AUTHORIZE_URL);
	
	public static void main(String[] args) throws Exception
	{  		
		getUserAccessToken ();
	}
		
	public static void getUserAccessToken () throws Exception
	{
		String authUrl = PROVIDER.retrieveRequestToken(CONSUMER, OAuth.OUT_OF_BAND);
        System.out.println("Authorization URL:"); 
        System.out.println(authUrl);
//        
//        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
//        String verification = br.readLine();
		
        //Try to get the oauth_verifier string programaticaly
		DefaultHttpClient httpclient = new DefaultHttpClient();

        HttpGet httpget = new HttpGet(authUrl);

        HttpResponse response = httpclient.execute(httpget);
        HttpEntity entity = response.getEntity();
        
		
        String verification = null;
        
        // Scoop.it is not sending back oauth_callback_confirmed=true  
		PROVIDER.setOAuth10a(true);
        PROVIDER.retrieveAccessToken(CONSUMER, verification);
        LOGGER.info("Access token acquired");
	}
	
	public static void testAPIConnection () throws Exception
	{
		URL url = new URL (BASE_API_URL + "/api/1/test");
        
        HttpURLConnection request = (HttpURLConnection) url.openConnection();

        
        // sign the request (consumer is a Signpost DefaultOAuthConsumer)
        CONSUMER.sign(request);

        // send the request
        request.connect();
        InputStream in = (InputStream) request.getContent();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        String curLine;
        while((curLine = reader.readLine()) != null)
        {
        	System.out.println(curLine);
        }
	}
	
	public static void preparePost (String postURL) throws Exception
	{
		URL url = new URL (BASE_API_URL + "/api/1/post");
		
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        String parameters = "action=prepare&url=";
        parameters += URLEncoder.encode(postURL, "UTF-8");
        connection.setRequestMethod("POST");
        
        connection.setRequestProperty("Content-Length", "" + 
                Integer.toString(parameters.getBytes().length));
       connection.setRequestProperty("Content-Language", "en-US");  
 			
       connection.setUseCaches (false);
       connection.setDoInput(true);
       connection.setDoOutput(true);
       CONSUMER.sign(connection);

       //Send request
       DataOutputStream wr = new DataOutputStream (
                   connection.getOutputStream ());
       wr.writeBytes (parameters);
       wr.flush ();
       wr.close ();
       
       InputStream is = connection.getInputStream();
       BufferedReader reader = new BufferedReader(new InputStreamReader(is));
       String line;
       while((line = reader.readLine()) != null) 
       {
         System.out.println(line);
       }
       reader.close();
	}
	
    
	public static Map<String, String> getQueryMap(String query)
	{
	    String[] params = query.split("&");
	    Map<String, String> map = new HashMap<String, String>();
	    for (String param : params)
	    {
	        String name = param.split("=")[0];
	        String value = param.split("=")[1];
	        map.put(name, value);
	    }
	    return map;
	}

}
