from __future__ import unicode_literals
from django.shortcuts import render, HttpResponse, redirect
from models import *
from django.contrib import messages
import re
import bcrypt
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

def index(request):
	return render(request, 'form/index.html')

def registration(request):
	errors = []
	if len(request.POST['first_name']) < 2:
		errors.append("First name must be at least 2 characters")
	if len(request.POST['last_name']) < 2:
		errors.append("Last name must be at least 2 characters")
	if len(request.POST['password']) < 2:
		errors.append("Password must be at least 2 characters")
	if request.POST['password'] != request.POST['confirm']:
		errors.append("Password and password confirmation don't match. Try again!")
	if not EMAIL_REGEX.match(request.POST['email']):
		messages.error(request,"Invalid Email")
            
	if errors:
		for err in errors:
			messages.error(request, err)
			print(errors)
		return redirect('/')
	
	else:	
		try:
			User.objects.get(email=request.POST['email'])
			messages.error(request, "User with that email already exists.")
			return redirect('/')
		except User.DoesNotExist:
			hashpw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
			user = User.objects.create(first_name=request.POST['first_name'],\
									last_name=request.POST['last_name'],\
									password = hashpw,\
									email = request.POST['email'])
			request.session['message'] = "You are registered"
			request.session['user_id'] = user.id
			return redirect('/success')

def login(request):
	if not request.POST['email']:
		messages.error(request, "Please enter your email")
		return redirect('/')

	if not request.POST['password']:
		messages.error(request, "Please enter your password")
		return redirect('/')
	try:
		user = User.objects.get(email = request.POST['email'])

		if bcrypt.checkpw(request.POST['password'].encode(), user.password.encode()):
			request.session['user_id'] = user.id
			request.session['message'] = "You are logged in"
			return redirect('/success')
		else:
			messages.error(request, 'Email or password are incorrect')
			return redirect('/')
	except User.DoesNotExist:
		messages.error(request, "Email doesn't exist.")
		return redirect('/')

def success(request):
	context = {
	'user': User.objects.get(id = request.session['user_id'])
	}    
	return render(request, 'form/successpage.html', context)

def logout(request):
	request.session.clear()
	return redirect('/')