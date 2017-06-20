import os
import jinja2
import webapp2
import re
import hmac
import hashlib
import random

from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def valid_username(username):
    """Determines if given username follows restrictions

    Args:
        username (str): User name.

    Returns:
        True: If follows restrictions.
        False: Otherwise
    """
    USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')

    return USER_RE.match(username)


def valid_password(password):
    """Determines if given password follows restrictions

    Args:
        password (str): User password.

    Returns:
        True: If follows restrictions.
        False: Otherwise
    """
    PASSWORD_RE = re.compile(r'^.{3,20}$')

    return PASSWORD_RE.match(password)


def valid_email(email):
    """Determines if given email follows restrictions

    Args:
        email (str): User email.

    Returns:
        True: If follows restrictions.
        False: Otherwise
    """
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+.[\S]+$')

    if email == '':
        return True
    else:
        return EMAIL_RE.match(email)


def make_secure_val(user_id):
    """Used for hashing user ids into a cookie.

    Args:
        user_id (str): Id of the user.

    Returns:
        User_id | hash of user_id
    """
    SECRET = 'imsosecret'

    return '{}|{}'.format(user_id, hmac.new(SECRET, user_id).hexdigest())


def check_secure_val(secure_val):
    """Used for checking if user_id matches hashed value.

    Args:
        secure_val (str): Hashed user_id.

    Returns:
        User_id if it matches hashed value.
        False: Otherwise.
    """
    user_id = secure_val.split('|')[0]

    if secure_val == make_secure_val(user_id):
        return user_id


def make_salt():
    """Creates a random salt value for password hashing.

    Returns:
        A random salt value.
    """
    return ''.join(random.choice(letters) for x in xrange(5))


def make_pw_hash(name, password, salt=None):
    """Hashes a password using a salt value and user name.

    Args:
        name (str): User's name.
        password (str): User's password.
        salt (str): Random salt value.

    Returns:
        Hashed value, salt
    """
    if not salt:
        salt = make_salt()
    hexhash = hashlib.sha256(name + password + salt).hexdigest()
    return '{},{}'.format(hexhash, salt)


def valid_pw(name, password, hexhash_salt):
    """Determines if password is valid with given hash salt.

    Args:
        name (str): User's name.
        password (str): User's password.
        hexhash_salt (str): Hash value and salt.

    Returns:
        True: Password and hash value match.
        False: Otherwise.
    """
    salt = hexhash_salt.split(',')[1]
    return hexhash_salt == make_pw_hash(name, password, salt)


class PostLike(db.Model):
    """Database model for blog post likes.

    Attributes:
        post_id (str): The id of the blog post that has been liked.
        user_id (str): The id of the user that liked the blog post.
    """

    post_id = db.StringProperty(required=True)
    user_id = db.StringProperty(required=True)


class CommentLike(db.Model):
    """Database model for blog post comment likes.

    Attributes:
        comment_id (str): The id of the blog post comment being liked.
        user_id (str): The id of the user that like the blog post comment.
    """

    comment_id = db.StringProperty(required=True)
    user_id = db.StringProperty(required=True)


class Comment(db.Model):
    """Database model for blog post comments.

    Attributes:
        post_id (reference): Links the comment to the blog post.
        creator_id (str): Id of the user that made the comment.
        content (text): The comment text.
        created (datetime): Date and time the comment was made.
        likes (int): Counter for number of likes the comment has.
    """

    post_id = db.ReferenceProperty(required=True)
    creator_id = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(default=0)


class User(db.Model):
    """Database model for blog users.

    Attributes:
        name (str): User's username.
        pw_hash (str): Secure password hash for authentication.
        email (str): Email of the user.
    """

    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()


class BlogPost(db.Model):
    """Database model for blog posts.

    Attributes:
        subject (str): Subject title of the blog post.
        content (text): Blog text.
        created (datetime): Date and time the blog post was created.
        creator_id (str): Id of the user that created the blog post.
        likes (int): Counter for number of likes the blog post has.
    """

    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    creator_id = db.StringProperty(required=True)
    likes = db.IntegerProperty(default=0)


class Handler(webapp2.RequestHandler):
    """Base parent handler class."""

    def write(self, *a, **kw):
        """Simplifies writing to the page.

        Usage:
            self.write("Some String")
        """
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """Simpliefies rendering html strings.

        Usage:
            self.render_str(template, **params)
        """
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **params):
        """Simplifies rendering a template.

        Usage:
            self.render('name.html')
        """
        self.write(self.render_str(template, **params))

    def check_user_id_cookie(self):
        """Attempts to grab user id cookie if it exists.

        Returns:
            user_id (str): If user id cookie exists.
            Else: None.
        """
        user_id_cookie = self.request.cookies.get('user_id')

        if user_id_cookie:
            user_id = user_id_cookie.split('|')[0]
            if self.get_user_by_id(user_id):
                if check_secure_val(user_id_cookie):
                    return user_id
        return None

    def get_post_by_id(self, post_id):
        """Gets blog post object with given id.

        Args:
            post_id (str): Id of the blog post.

        Returns:
            BlogPost object with given id.
        """
        return BlogPost.get_by_id(int(post_id))

    def get_user_by_id(self, user_id):
        """Gets user object with given id.

        Args:
            user_id (str): Id of the user.

        Returns:
            User object with given id.
        """
        return User.get_by_id(int(user_id))

    def get_comment_by_id(self, comment_id):
        """Gets comment object with given id.

        Args:
            comment_id (str): Id of the comment.

        Returns:
            Comment object with given id.
        """
        return Comment.get_by_id(int(comment_id))

    def logout(self):
        """Resets user id cookie."""
        self.response.headers.add_header(
            'Set-Cookie',
            'user_id=; Path=/'
        )

    def login(self, user):
        """Sets user id cookie."""
        self.response.headers.add_header(
            'Set-Cookie',
            'user_id={}; Path=/'.format(make_secure_val(str(user.key().id())))
        )

    def get_post_likes(self, post_id):
        """Gets total number of likes on the blog post.

        Args:
            post_id (str): Id of the blog post.

        Returns:
            Blog post likes counter.
        """
        return PostLike.all().filter('post_id =', post_id)

    def get_posts(self):
        """Gets last 10 blog posts created.

        Returns:
            BlogPost list.
        """
        return BlogPost.all().order('-created').fetch(10)

    def user_exists(self, username):
        """Determines if user name is already used.

        Args:
            username (str): Name to be checked.

        Returns:
            User object: If username has been used already.
            None: Otherwise.
        """
        return User.all().filter('name =', username).get()

    def already_liked_post(self, post_id, user_id):
        """Checks if user has already liked the post.

        Args:
            post_id (str): Id of the post.
            user_id (str): Id of the current user.

        Returns:
            True: If user has already liked the post.
            False: Otherwise.
        """
        return PostLike.all().filter(
            'post_id =', post_id).filter('user_id =', user_id).get()

    def already_liked_comment(self, comment_id, user_id):
        """Checks if user has already liked the comment.

        Args:
            comment_id (str): Id of the comment.
            user_id (str): Id of the current user.

        Returns:
            True: If user has already liked the comment.
            False: Otherwise.
        """
        return CommentLike.all().filter(
            'comment_id =', comment_id).filter('user_id =', user_id).get()

    def nav_bar_action(self):
        """Determines if nav bar button has been pressed.

        Returns:
            Redirect action
            False: Otherwise.
        """
        if self.request.get('home', None):
            self.redirect('/blog')
        elif self.request.get('newpost', None):
            self.redirect('/blog/newpost')
        elif self.request.get('signup', None):
            self.redirect('/signup')
        elif self.request.get('login', None):
            self.redirect('/login')
        elif self.request.get('logout', None):
            self.redirect('/logout')
        else:
            return False


class BlogHandler(Handler):
    """Handles user interaction on the main blog page."""

    def get(self):
        """Displays main blog page."""
        blogposts = self.get_posts()
        error = self.request.get('error')
        comments = Comment.all().order('created')
        user_id = self.check_user_id_cookie()

        self.render(
            'blogposts.html', blogposts=blogposts, comments=comments,
            error=error, user_id=user_id
        )

    def post(self):
        """Determines what action user took on the blog."""
        if self.nav_bar_action() is False:
            user_id = self.check_user_id_cookie()

            if user_id:
                creator_id = self.request.get('creator_id')
                post_id = self.request.get('post_id')
                comment_id = self.request.get('comment_id')
                content = self.request.get('content')

                if self.request.get('edit_post', None):
                    self.edit_post(user_id, creator_id, post_id)
                elif self.request.get('delete_post', None):
                    self.delete_post(user_id, creator_id, post_id)
                elif self.request.get('like_post', None):
                    self.like_post(user_id, creator_id, post_id)
                elif self.request.get('submit_comment', None):
                    self.comment(user_id, post_id, content)
                elif self.request.get('edit_comment', None):
                    self.edit_comment(user_id, creator_id, comment_id)
                elif self.request.get('delete_comment', None):
                    self.delete_comment(user_id, creator_id, comment_id)
                elif self.request.get('like_comment', None):
                    self.like_comment(user_id, creator_id, comment_id)
            else:
                self.redirect(
                    '../login?error=' +
                    'Please login before contributing to the blog.'
                )

    def edit_post(self, user_id, creator_id, post_id):
        """Determines if post can be edited.

        If the current user is the creator of the post, then the user will be
        redirected to the url for editing the post. If not, the user will be
        redirected back to the blog given an error.

        Args:
            user_id (str): Id of the current user.
            creator_id (str): Id of the creator of the post.
            post_id (str): Id of the post.
        """
        if user_id == creator_id:
            self.redirect('/blog/edit-post?post_id=' + post_id)
        else:
            self.redirect(
                '/blog?error=' +
                'Sorry, you can only edit posts made by you.'
            )

    def delete_post(self, user_id, creator_id, post_id):
        """Determines if post can be deleted.

        If the current user is the creator of the post, then the user will be
        able to delete the post. If not, the user will be redirected back to
        the blog given an error.

        Args:
            user_id (str): Id of the current user.
            creator_id (str): Id of the creator of the post.
            post_id (str): Id of the post.
        """
        if user_id == creator_id:
            blogpost = self.get_post_by_id(post_id)
            if blogpost:
                blogpost.delete()

            self.redirect('/blog')
        else:
            self.redirect(
                '/blog?error=' +
                'Sorry, you can only delete posts made by you.'
            )

    def like_post(self, user_id, creator_id, post_id):
        """Determines if post can be liked.

        If the current user is the creator of the post, then the user will be
        able to like the post. If not, the user will be redirected back to
        the blog given an error.

        Args:
            user_id (str): Id of the current user.
            creator_id (str): Id of the creator of the post.
            post_id (str): Id of the post.
        """
        if user_id != creator_id:
            already_liked = self.already_liked_post(post_id, user_id)
            blogpost = self.get_post_by_id(post_id)

            if already_liked:
                already_liked.delete()
                blogpost.likes -= 1
                blogpost.put()

            else:
                like = PostLike(post_id=post_id, user_id=user_id)
                like.put()
                blogpost.likes += 1
                blogpost.put()

            self.redirect('/blog')
        else:
            self.redirect(
                '/blog?error=' +
                'Sorry, you can not like your own posts.'
            )

    def comment(self, creator_id, post_id, content):
        """Adds the comment to the post.

        Grabs the current user's id and creates a comment on the post.

        Args:
            creator_id (str): Id of the current user.
            post_id (str): Id of the post.
            content (str): Text of the comment.
        """
        blogpost = self.get_post_by_id(post_id)
        comment = Comment(
            post_id=blogpost.key(), creator_id=creator_id, content=content
        )
        comment.put()

        self.redirect('/blog')

    def edit_comment(self, user_id, creator_id, comment_id):
        """Determines if comment can be edited.

        If the current user is the creator of the comment, then the user will
        be able to edit the comment. If not, the user will be redirected back
        to the blog given an error.

        Args:
            user_id (str): Id of the current user.
            creator_id (str): Id of the creator of the comment.
            comment_id (str): Id of the comment.
        """
        if user_id == creator_id:
            self.redirect('/blog/edit-comment?comment_id=' + comment_id)
        else:
            self.redirect(
                '/blog?error=' +
                'Sorry, you can only edit your own comments.'
            )

    def delete_comment(self, user_id, creator_id, comment_id):
        """Determines if comment can be deleted.

        If the current user is the creator of the comment, then the user will
        be able to delete the comment. If not, the user will be redirected
        back to the blog given an error.

        Args:
            user_id (str): Id of the current user.
            creator_id (str): Id of the creator of the comment.
            comment_id (str): Id of the comment.
        """
        if user_id == creator_id:
            comment = self.get_comment_by_id(comment_id)
            if comment:
                comment.delete()

            self.redirect('/blog')
        else:
            self.redirect(
                '/blog?error=' +
                'Sorry, you can only delete comments made by you.'
            )

    def like_comment(self, user_id, creator_id, comment_id):
        """Determines if comment can be liked.

        If the current user is the creator of the comment, then the user will
        be able to like the comment. If not, the user will be redirected back
        to the blog given an error.

        Args:
            user_id (str): Id of the current user.
            creator_id (str): Id of the creator of the comment.
            comment_id (str): Id of the comment.
        """
        if user_id != creator_id:
            already_liked = self.already_liked_comment(comment_id, user_id)
            comment = self.get_comment_by_id(comment_id)

            if already_liked:
                already_liked.delete()
                comment.likes -= 1
                comment.put()
            else:
                like = CommentLike(comment_id=comment_id, user_id=user_id)
                like.put()
                comment.likes += 1
                comment.put()

            self.redirect('/blog')
        else:
            self.redirect(
                '/blog?error=' +
                'Sorry, you can not like your own comments.'
            )


class NewAddedPostHandler(Handler):
    """Handles user interaction on the newly added post page."""

    def get(self, post_id):
        """Displays static page for a newly added post.

        Args:
            post_id (str): Id of the new post.
        """
        user_id = self.check_user_id_cookie()
        blogpost = self.get_post_by_id(post_id)

        self.render(
            'newaddedpost.html', blogpost=blogpost, user_id=user_id
        )

    def post(self, post_id):
        """Determines user action on newly added post page.

        Args:
            post_id (str): Id of the new post.
        """
        self.nav_bar_action()


class NewPostHandler(Handler):
    """Handles user interaction on the create a new post page."""

    def get(self):
        """Displays create new post page."""
        user_id = self.check_user_id_cookie()

        if user_id:
            self.render('newpost.html', user_id=user_id)
        else:
            self.redirect(
                '../login?error=' +
                'Please login before contributing to the blog.'
            )

    def post(self):
        """Determines user action on create new post page.

        If new post is submited, subject and content must be filled out or
        user will be redirected to back to new post page with an error.
        """
        if self.nav_bar_action() is False:
            if self.request.get('cancel'):
                self.redirect('/blog')
            else:
                subject = self.request.get('subject')
                content = self.request.get('content')
                user_id = self.check_user_id_cookie()

                if subject and content and user_id:
                    blogpost = BlogPost(
                        subject=subject, content=content, creator_id=user_id
                    )
                    blogpost.put()

                    self.redirect('/blog/{}'.format(blogpost.key().id()))

                else:
                    self.render(
                        'newpost.html', subject=subject, content=content,
                        input_error='Subject and content, please!'
                    )


class SignupHandler(Handler):
    """Handles user interaction on the signup page."""

    def get(self):
        """Displays the signup page."""
        user_id = self.check_user_id_cookie()

        self.render('signup.html', user_id=user_id)

    def post(self):
        """Determines user action on signup page.

        On submit, user inputs are verified and redirected to signup page
        if any value is invalid.
        """
        if self.nav_bar_action() is False:
            error = False
            username = self.request.get('username')
            password = self.request.get('password')
            verify = self.request.get('verify')
            email = self.request.get('email')
            name_used = self.user_exists(username)

            params = dict(username=username, email=email)

            if name_used:
                params['error_username_exists'] = 'Username already exists.'
                error = True

            if not valid_username(username):
                params['error_username'] = "That's not a valid username."
                error = True

            if not valid_password(password):
                params['error_password'] = "That wasn't a valid password."
                error = True
            elif password != verify:
                params['error_verify_pws'] = "Your passwords didn't match."
                error = True

            if not valid_email(email):
                params['error_email'] = "That's not a valid email."
                error = True

            if error:
                self.render('signup.html', **params)
            else:
                pw_hash = make_pw_hash(username, password)
                user = User(name=username, pw_hash=pw_hash, email=email)
                user.put()

                self.login(user)
                self.redirect('/welcome')


class WelcomeHandler(Handler):
    """Handles user interaction on the welcome user page."""

    def get(self):
        """Displays welcome page if a user is logged in."""
        user_id = self.check_user_id_cookie()

        if user_id:
            username = self.get_user_by_id(user_id).name

            self.render(
                'welcome.html', username=username, user_id=user_id
            )
        else:
            self.redirect('../login?error=' + 'Please login first.')

    def post(self):
        """Determines user interaction on welcome page."""
        self.nav_bar_action()


class LoginHandler(Handler):
    """Handles user interaction on the login page."""

    def get(self):
        """Displays login page."""
        error = self.request.get('error')
        user_id = self.check_user_id_cookie()

        self.render('login.html', error=error, user_id=user_id)

    def post(self):
        """Determines user action on login page.

        On submit, if user inputs are valid and the user exists in the
        database, user is logged in and redirected to welcome page.
        If not, user is redirected to login page with an error.
        """
        if self.nav_bar_action() is False:
            username = self.request.get('username')
            password = self.request.get('password')
            user = self.user_exists(username)

            if username and password and user:
                if valid_pw(username, password, user.pw_hash):
                    self.login(user)
                    self.redirect('/welcome')
                else:
                    self.render('login.html', error='Invalid login')
            else:
                self.render('login.html', error='Invalid login')


class LogoutHandler(Handler):
    """Handles user interaction with logout."""

    def get(self):
        """Logs user out and redirects to login page."""
        self.logout()
        self.redirect('/login')


class EditPostHandler(Handler):
    """Handles user interaction on the edit post page."""

    def get(self):
        """Displays edit post page."""
        error = self.request.get('error')
        post_id = self.request.get('post_id')
        blogpost = self.get_post_by_id(post_id)
        user_id = self.check_user_id_cookie()

        self.render(
            'edit-post.html', blogpost=blogpost, error=error,
            user_id=user_id
        )

    def post(self):
        """Determines user action on edit post page.

        Checks if user input is valid. If yes, overwrites blog post in database
        with new values and redirects to main blog page. If no, redirects
        to edit post page with error.
        """
        if self.nav_bar_action() is False:
            if self.request.get('cancel'):
                self.redirect('/blog')
            else:
                subject = self.request.get('subject')
                content = self.request.get('content')
                post_id = self.request.get('post_id')
                user_id = self.check_user_id_cookie()
                blogpost = self.get_post_by_id(post_id)

                if user_id and blogpost and blogpost.creator_id == user_id:
                    if subject and content:
                        blogpost.subject = subject
                        blogpost.content = content
                        blogpost.put()

                        self.redirect('/blog')
                    else:
                        self.redirect(
                            '/blog/edit-post?error={}&post_id={}'
                            .format(
                                'Subject and content can not be empty.',
                                post_id
                            )
                        )
                else:
                    self.redirect(
                        '/blog?error=' +
                        'You can not edit that post.'
                    )


class EditCommentHandler(Handler):
    """Handles user interaction on the edit comment page."""

    def get(self):
        """Displays edit comment page."""
        comment_id = self.request.get('comment_id')
        comment = self.get_comment_by_id(comment_id)
        user_id = self.check_user_id_cookie()

        self.render('edit-comment.html', comment=comment, user_id=user_id)

    def post(self):
        """Determines user action on edit comment page.

        Checks if user input is valid. If yes, overwrites comment in database
        with new values and redirects to main blog page. If no, redirects
        user to edit comment page with error.
        """
        if self.nav_bar_action() is False:
            if self.request.get('cancel'):
                self.redirect('/blog')
            else:
                comment_id = self.request.get('comment_id')
                content = self.request.get('content')
                user_id = self.check_user_id_cookie()
                comment = self.get_comment_by_id(comment_id)

                if user_id and comment and comment.creator_id == user_id:
                    if content:
                        comment.content = content
                        comment.put()

                        self.redirect('/blog')
                    else:
                        self.redirect(
                            '/blog/edit-comment?error={}&comment_id={}'
                            .format('Please enter a comment', comment_id)
                        )
                else:
                    self.redirect(
                        '/blog?error=' +
                        'You can not edit that comment.'
                    )

app = webapp2.WSGIApplication(
    [('/blog', BlogHandler),
     ('/blog/newpost', NewPostHandler),
     ('/blog/(\d+)', NewAddedPostHandler),
     ('/signup', SignupHandler),
     ('/welcome', WelcomeHandler),
     ('/login', LoginHandler),
     ('/logout', LogoutHandler),
     ('/blog/edit-post', EditPostHandler),
     ('/blog/edit-comment', EditCommentHandler)], debug=True)
