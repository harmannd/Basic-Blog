import os
import jinja2
import webapp2
import re

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

class BlogPost(db.Model):
    subject = db.StringProperty(required = True)
    blog = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **params):
        self.write(self.render_str(template, **params))

class MainPage(Handler):
    def get(self):
        blogposts = db.GqlQuery("SELECT * FROM BlogPost "
                                "ORDER By created DESC LIMIT 10")
        self.render('blogposts.html', blogposts = blogposts)

class NewAddedPost(Handler):
    def get(self, post_id):
        blogpost = BlogPost.get_by_id(int(post_id))
        self.render('newaddedpost.html', blogpost = blogpost)

class NewPost(Handler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        subject = self.request.get('subject')
        blog = self.request.get('blog')

        if subject and blog:
            b = BlogPost(subject = subject, blog = blog)
            b.put()

            self.redirect('/blog/{}'.format(b.key().id()))
        else:
            self.render('newpost.html', subject = subject, blog = blog, input_error = "Subject and content, please!")

app = webapp2.WSGIApplication([('/blog', MainPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/(\d+)', NewAddedPost)],
                                debug=True)