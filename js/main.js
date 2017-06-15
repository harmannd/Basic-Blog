function Like(blogpostkey){
    $.ajax({
      type: "POST",
      url: "/like",
      dataType: 'json',
      data: JSON.stringify({ "blogpostkey": blogpostkey})
    });
};
