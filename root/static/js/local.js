$(function() {
  $('#pool-control').select2({
    width: '100%',
    placeholder: "Select a Pool",
    allowClear: true,
    formatResult: formatResultMultiPool
  });
})

function formatResultMultiPool(data) {
  var size = $(data.element).data('size');
  var free = $(data.element).data('free');
  var hasClass = typeof classAttr != 'undefined';
  classAttr = hasClass ? ' ' + classAttr : '';

  var $result = $(
    '<div class="row">' +
    '<div class="col-md-3 col-xs-3' + classAttr + '">' + data.text + '</div>' +
    '<div class="col-md-4 col-xs-4' + classAttr + '">' + size + '</div>' +
    '<div class="col-md-4 col-xs-4' + classAttr + '">' + free + '</div>' +
    '</div>'
  );
  return $result;
}

$("i.icon").popover({'container':'body','trigger':'hover'});
$('.bootstrap-tooltip').tooltip();
$('[data-toggle="switch"]').bootstrapSwitch();


$('#AddUpload').on('show.bs.modal', function (event) {
        show_progress();
        var span        = $(event.relatedTarget);
        var modal               = $(this);
        var title = span.data('title');
	if (typeof title == 'undefined') 
	      title="generic";
        modal.find('.modal-title').text("Upload "+title+" file");
        file_upload_type=title;
        if (title == 'iso')
           document.getElementById("id_file").accept= ".iso";
        if (title == 'vm')
           document.getElementById("id_file").accept= ".qcow2, .img, .bxrc, .cloop, .cow, .dmg, .nbd, .parallels, .qcow, .qed, .vdi, .vhdx, .vmdk, .vvfat";
});



//$(function() {
// $( "#AddUpload" ).on('shown', function(){
function show_progress(){
    var div = document.getElementById('upload_progress');
    if (div == null )
         return;
    div.style.visibility = 'hidden';
    $("#cancelBtn").hide();
    $('form').ajaxForm({
      error: function(response, status, e){
          eModal.alert('An error occured during file uploading');
      },
        beforeSend: function(xhr) {
            div.style.visibility = 'visible';
	    $("#cancelBtn").show();
	    $('#cancelBtn').click(xhr.abort)
        },
        uploadProgress: function(event, position, total, percentComplete) {
            var percentVal = percentComplete;
            if (percentVal == '100') {
                                $("#cancelBtn").hide();
                                $("#upload_progress_bar").text("Please wait while the file is moved to storagepool");
            }
	    else  {
            	$("#upload_progress_bar").css("width", percentVal + "%")
                                         .attr("aria-valuenow", percentVal)
                                         .text(percentVal + "%");
	       	}			 
        },
	success: function (xhr) {
            $('#cancelBtn').click(xhr.abort)
        },
        complete: function(xhr) {
         $("#cancelBtn").hide();
         div.style.visibility = 'hidden'; 
         var percentVal = '0';
         $("#upload_progress_bar").css("width", percentVal + "%")
                                         .attr("aria-valuenow", percentVal)
                                         .text(percentVal + "%");

           $('#AddUpload').modal('hide');
           if ( typeof file_upload_type !== 'undefined'  )
	     if ((file_upload_type == 'vm') || (file_upload_type == 'iso') ) {
                var gr_start,gr_end,options;
            
                if (file_upload_type == 'vm') 
                    gr_start='<optgroup class=\'def-cursor\' label=\'Uploaded Image Files\' data-size=\'\' data-format=\'\'>';
                if (file_upload_type == 'iso')
                    gr_start='<optgroup class=\'def-cursor\' label=\'Uploaded ISO Files\' data-size=\'\' data-format=\'\'>';
                gr_end='</optgroup';
                var storage_pool = $('#storage_pool_upload').find(':selected').data('path');
                
                for (var x = 0; x < document.getElementById('id_file').files.length; x++) {
                    filename = document.getElementById('id_file').files[x];
                    var size=formatBytes(filename.size);
                    var extension=filename.name.split('.').pop();
                    var image_path=storage_pool+'/'+filename.name;
                    options=options+'<option selected="selected" value="'+image_path+'" data-size="'+size+'" data-format="'+extension+'">'+filename.name+'</option>';
                }
                if (file_upload_type == 'vm')
                     $('#image-control').append(gr_start+options+gr_end).trigger('change');
                if (file_upload_type == 'iso'){
                     $('#cdroms-control').append(gr_start+options+gr_end).trigger('change');
                     $('#boot-control').val(null).trigger('change');
                     document.getElementById("boot-control_div").style.display = "block";
                     $('#boot-control').append(gr_start+options+gr_end).trigger('change');
		     }
	       	     
         }
	 else {
	   window.location.reload(true);
	   }
        }
         });
} 

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';

    var k = 1024;
    var dm = decimals < 0 ? 0 : decimals;
    var sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

    var idx = Math.floor(Math.log(bytes) / Math.log(k));

    var fmt_str=parseFloat((bytes / Math.pow(k, idx)).toFixed(dm)) + ' ' + sizes[idx];
    return fmt_str;
}

