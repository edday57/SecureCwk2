package comp3911.cwk2;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;
import java.io.PrintWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.MessageDigest;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

@SuppressWarnings("serial")
public class SignUpServerlet extends HttpServlet {

  private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
  private static String SECRET_KEY= "SECRET";
  private static final String USER_QUERY = "select * from user where username='%s'";
  private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
  private Connection database;

  @Override
  public void init() throws ServletException {
    configureTemplateEngine();
    connectToDatabase();
  }

  private void configureTemplateEngine() throws ServletException {
    try {
      fm.setDirectoryForTemplateLoading(new File("./templates"));
      fm.setDefaultEncoding("UTF-8");
      fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
      fm.setLogTemplateExceptions(false);
      fm.setWrapUncheckedExceptions(true);
    }
    catch (IOException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private void connectToDatabase() throws ServletException {
    try {
      database = DriverManager.getConnection(CONNECTION_URL);
    }
    catch (SQLException error) {
      throw new ServletException(error.getMessage());
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
   throws ServletException, IOException {
     // Get form parameters
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    String name = request.getParameter("name");
    String key = request.getParameter("key");
    //lowercase usernames only
    username = username.toLowerCase();
    try {
      PrintWriter out = response.getWriter();
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
      //Verify user does not exist
      if(userExists(username)){
          out.print("User already exists");
          out.flush();
          return;
      }
      if (authenticated(key)) {
        if(isValidPass(username,password, name)){
          MessageDigest digest = MessageDigest.getInstance("SHA-256");
          byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
          String encoded = Base64.getEncoder().encodeToString(hash);
          try {
            Statement stmt = database.createStatement();
            String op;
            op = "INSERT INTO user(name, username, password) VALUES('"+name+"','"+username+"','"+encoded+"');";
            stmt.executeUpdate(op);
            stmt.close();
          } catch (SQLException e) {
            e.printStackTrace();
          }
          //User is allowed to sign up and password is valid
          out.print("User '"+username+"' created");
          out.flush();
        }
        else{
          out.print("Password is not secure.");
          out.flush();
        }
      }
      
      
    }
    catch (Exception error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  private boolean authenticated(String key){
    if(key.equals(SECRET_KEY)){
      return true;
    }
    return false;
  }

  private boolean isValidPass(String username, String password, String name){
    //Length > 8
    if (password.length()>=8){
      //Contains number
      if(password.matches(".*\\d.*")){
        //If special characters
        Pattern p = Pattern.compile("[^A-Za-z0-9]");
        Matcher m = p.matcher(password);
        boolean b = m.find();
        if(b){
          //If name included
          String lowerpass = password.toLowerCase();
          if(lowerpass.indexOf(name.toLowerCase())==-1){
            //If username included
            if(lowerpass.indexOf(username.toLowerCase())==-1){
              return true;
            }
          }
        }
      }     
    }

    return false;
  }
  private boolean userExists(String username) throws SQLException {
    String query = String.format(USER_QUERY, username);
    try (Statement stmt = database.createStatement()) {
      ResultSet results = stmt.executeQuery(query);
      return results.next();
    }
  }

}
