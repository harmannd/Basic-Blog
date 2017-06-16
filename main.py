import os
import jinja2
import webapp2
import re
import hmac
import hashlib
import random
import json

from string import letters
from google.appengine.ext import db

SECRET = 'imsosecret'
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASSWORD_RE.match(password)

def valid_email(email):
    if email == "":
        return True
    else:
        return EMAIL_RE.match(email)

def make_secure_val(val):
    return "{}|{}".format(val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt():
    return ''.join(random.choice(letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    hexhash = hashlib.sha256(name + pw + salt).hexdigest()
    return '{},{}'.format(hexhash, salt)

def valid_pw(name, password, hexhash_salt):
    salt = hexhash_salt.split(',')[1]
    return hexhash_salt == make_pw_hash(name, password, salt)

class Like(db.Model):
    post_id = db.StringProperty(required = True)
    user_id = db.StringProperty(required = True)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

class BlogPost(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    creator_id = db.StringProperty(required = True)
    likes = db.IntegerProperty(default = 0)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **params):
        self.write(self.render_str(template, **params))

    def user_id_cookie(self):
        user_id_cookie = self.request.cookies.get('user_id')

        if user_id_cookie:
            user_id = user_id_cookie.split('|')[0]
            if user_id != None:
                return user_id
            else:
                self.redirect('../login?error=' + 'Please login before contributing to the blog.')
        else:
            self.redirect('../login?error=' + 'Please login before contributing to the blog.')

    def get_post_by_id(self, post_id):
        return BlogPost.get_by_id(int(post_id))

    def get_user_by_id(self, user_id):
        return User.get_by_id(int(user_id))

    def login(self, user):
        self.response.headers.add_header('Set-Cookie', 'user_id={}; Path=/'.format(make_secure_val(str(user.key().id()))))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def get_post_likes(self, post_id):
        return db.GqlQuery("SELECT * FROM Like "
                           "WHERE Like.post_id == :1 ", post_id)

    def get_posts(self):
        return db.GqlQuery("SELECT * FROM BlogPost "
                           "ORDER By created DESC LIMIT 10 ")

    def already_liked_post(self, post_id, user_id):
        likes = Like.all()
        return likes.filter('post_id =', post_id).filter('user_id =', user_id).fetch(1)

class BlogHandler(Handler):
    def get(self):
        blogposts = self.get_posts()
        error = self.request.get('error')

        self.render('blogposts.html', blogposts = blogposts, error = error)

    def post(self):
        creator_id = self.request.get('creator_id')
        post_id = self.request.get('post_id')
        user_id = self.user_id_cookie()

        if user_id and self.get_user_by_id(user_id):
            if self.request.get('edit', None):
                self.edit(user_id, creator_id, post_id)
            elif self.request.get('delete', None):
                self.delete(user_id, creator_id, post_id)
            elif self.request.get('like', None):
                self.like(user_id, creator_id, post_id)
            else:
                self.write("Other")
        else:
            self.redirect('../login?error=' + 'Please login before contributing to the blog.')

    def edit(self, user_id, creator_id, post_id):
        if user_id == creator_id:
           self.redirect('/blog/edit?post_id=' + post_id)
        else:
           self.redirect('/blog?error=' + 'Sorry, you can only edit posts made by you.')

    def delete(self, user_id, creator_id, post_id):
        if user_id == creator_id:
            blogpost = self.get_post_by_id(post_id)
            blogpost.delete()
            self.redirect('/blog')
        else:
            self.redirect('/blog?error=' + 'Sorry, you can only delete posts made by you.')

    def like(self, user_id, creator_id, post_id):
        if user_id != creator_id:
            already_liked = self.already_liked_post(post_id, user_id)
            blogpost = self.get_post_by_id(post_id)

            if len(already_liked) > 0:
                already_liked[0].delete()
                blogpost.likes -= 1
                blogpost.put()

            else:
                like = Like(post_id = post_id, user_id = user_id)
                like.put()
                blogpost.likes += 1
                blogpost.put()

            self.redirect('/blog')
        else:
            self.redirect('/blog?error=' + 'Sorry, you can not like your own posts')

class NewAddedPostHandler(Handler):
    def get(self, post_id):
        blogpost = self.get_post_by_id(post_id)
        self.render('newaddedpost.html', blogpost = blogpost)

class NewPostHandler(Handler):
    def get(self):
        user_id = self.user_id_cookie()

        if user_id and self.get_user_by_id(user_id):
            self.render('newpost.html')
        else:
            self.redirect('../login?error=' + 'Please login before contributing to the blog.')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        user_id = self.user_id_cookie()

        if subject and content and user_id:
            blogpost = BlogPost(subject = subject, content = content, creator_id = user_id)
            blogpost.put()

            self.redirect('/blog/{}'.format(blogpost.key().id()))

        else:
            self.render('newpost.html', subject = subject, content = content, input_error = "Subject and content, please!")


class SignupHandler(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            error = True
        elif password != verify:
            params['error_verify_password'] = "Your passwords didn't match."
            error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            error = True

        if error:
            self.render('signup.html', **params)
        else:
            pw_hash = make_pw_hash(username, password)
            user = User(name = username, pw_hash = pw_hash, email = email)
            user.put()

            self.login(user)
            self.redirect('/welcome')

class WelcomeHandler(Handler):
    def get(self):
        user_id = self.user_id_cookie()

        if user_id:
            username = self.get_user_by_id(user_id).name
            self.render('welcome.html', username = username)
        else:
            self.redirect('../login?error=' + 'Please login first.')


class LoginHandler(Handler):
    def get(self):
        error = self.request.get('error')

        self.render('login.html', error = error)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        users = db.GqlQuery("SELECT * FROM User "
                            "WHERE name = :1", username).fetch(limit = None)

        if username and password and len(users) > 0:
            for user in users:
                if valid_pw(username, password, user.pw_hash):
                    self.login(user)
                    self.redirect('/welcome')
        else:
            self.render('login.html', error = "Invalid login")

class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')

class EditHandler(Handler):
    def get(self):
        error = self.request.get('error')
        post_id = self.request.get('post_id')
        blogpost = self.get_post_by_id(post_id)

        self.render('edit.html', blogpost = blogpost, error = error)

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        post_id = self.request.get('post_id')

        if post_id and subject and content:
            blogpost = self.get_post_by_id(post_id)
            blogpost.subject = subject
            blogpost.content = content
            blogpost.put()

            self.redirect('/blog')
        else:
            self.redirect('/blog/edit?error={}&post_id={}'.format('Subject and content can not be empty.', post_id))

app = webapp2.WSGIApplication([('/blog', BlogHandler),
                               ('/blog/newpost', NewPostHandler),
                               ('/blog/(\d+)', NewAddedPostHandler),
                               ('/signup', SignupHandler),
                               ('/welcome', WelcomeHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/blog/edit', EditHandler)],
                                debug=True)