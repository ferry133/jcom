# Program:
# 	This program shows the user's choice
# History:
# 2026/03/22	Larry	First release
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH


if [ $# != 1 ]; then
	echo "Incorrect number of parameters."
	echo "reconcile helmrelease: ${0} target_helmrelease"
    exit 0
fi

#kubectl get helmrelease -A | awk '{FS=" "}  {print $1 " " $2}'
#kubectl get helmrelease -A | awk '{FS=" "} $2 == "'${1}'" {print $1 " " $2}'

kubectl get helmrelease -A | awk '{FS=" "} $2=="'${1}'" {print "namespace is :" $1 " and helmrelease name is :" $2}'

namespace="unknown"

#echo "1 The namespace of helmrelease ${1} is ${namespace}"

kubectl get helmrelease -A | awk '{FS=" "} $2=="'${1}'" {namespace=$1; print "2 The namespace of hr " "'${1}'" " is " namespace }'
#kubectl get helmrelease -A | awk '{FS=" "} $2=="'${1}'" {time}'
kubectl get helmrelease -A | awk '{FS=" "} $2=="'${1}'" {BEGIN kubectl delete hr $2 -n $1}'
#kubectl get helmrelease -A | awk '{FS=" "} $2=="'${1}'" {kubectl get all}'
#kubectl get helmrelease -A | awk '{FS=" "} $2=="'${1}'" {kubectl -n $1 get hr }'

#echo "The namespace of helmrelease ${1} is ${namespace}"



#echo "The script name is        ==> ${0}"
#echo "Total parameter number is ==> $#"
#[ "$#" -lt 2 ] && echo "The number of parameter is less than 2.  Stop here." && exit 0
#echo "Your whole parameter is   ==> '$@'"
#echo "The 1st parameter         ==> ${1}"
#echo "The 2nd parameter         ==> ${2}"

#mkdir $PWD/talos/clusterconfig
#cp ./config.gen/*kubeconfig.yaml $KUBECONFIG
#cp ./config.gen/*talosconfig.yaml $TALOSCONFIG

#cp ./config.gen/*kubeconfig.yaml ./kubeconfig
#cp ./config.gen/*talosconfig.yaml ./talosconfig

#export KUBECONFIG=$PWD/kubeconfig
#export TALOSCONFIG=$PWD/talosconfig

